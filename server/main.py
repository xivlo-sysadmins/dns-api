import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.zone

import json

from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Response, status
from fastapi.responses import PlainTextResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from datetime import datetime
from os import environ
from passlib.context import CryptContext
from pathlib import Path
from subprocess import run

if "SETTINGS" in environ:
    settings_file_name = environ['SETTINGS']
else:
    settings_file_name = "settings.json"
with open(settings_file_name) as settings_file:
    settings = json.load(settings_file)

pwd_context = CryptContext(schemes=["pbkdf2_sha256"])

app = FastAPI()

security = HTTPBasic()


def authenticate(credentials):
    if credentials.username not in settings['users']:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unknown user",
            headers={"WWW-Authenticate": "Basic"}
        )
    user = settings['users'][credentials.username]
    if not pwd_context.verify(credentials.password, user['hashed_password']):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Password is incorrect",
            headers={"WWW-Authenticate": "Basic"}
        )
    return user


def is_authorized(user, name, zone_name) -> bool:
    zone_name_str = str(zone_name.relativize(origin=dns.name.from_text('.')))
    if user['zones'][zone_name_str]['grant_all']:
        return True
    if str(name.relativize(origin=zone_name)) in user['zones'][zone_name_str]['names']:
        return True
    for wildcard in user['zones'][zone_name_str]['wildcards']:
        if name.is_subdomain(dns.name.from_text(wildcard, origin=zone_name)):
            return True
    return False


def upserial(zone):
    rdataset = zone.find_rdataset('@', dns.rdatatype.SOA)
    ttl = rdataset.ttl
    soa = rdataset[0].to_text().split()
    serial = int(soa[2])

    base = int(datetime.now().strftime('%Y%m%d')) * 100
    if base > serial:
        serial = base
    else:
        serial += 1
    soa[2] = str(serial)

    rdataset.clear()
    rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.SOA, ' '.join(soa))
    rdataset.add(rdata, ttl=ttl)


@app.get("/update/{zone_name}/show", status_code=status.HTTP_200_OK)
async def show(response: Response, zone_name: str,
               credentials: HTTPBasicCredentials = Depends(security)):
    user = authenticate(credentials)
    try:
        zone_name = dns.name.from_text(zone_name)
    except dns.name.BadEscape as e:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {"status": "err", "param": "name", "message": e.msg}
    zone_name_str = str(zone_name.relativize(origin=dns.name.from_text('.')))
    
    if zone_name_str not in user['zones']:
        response.status_code = status.HTTP_403_FORBIDDEN
        return {"status": "err", "message": "Not authorized for this zone"}

    filename = "{zone_name}.zone".format(zone_name=zone_name_str)
    filepath = Path(settings['zones_path'], filename)
    zone = dns.zone.from_file(str(filepath), origin=zone_name)

    return PlainTextResponse(zone.to_text())


@app.put("/update/{zone_name}/add", status_code=status.HTTP_200_OK)
async def add(response: Response, zone_name: str, name: str, rtype: str, value: str,
              ttl: Optional[int] = None, credentials: HTTPBasicCredentials = Depends(security)):
    user = authenticate(credentials)
    try:
        zone_name = dns.name.from_text(zone_name)
    except dns.name.BadEscape as e:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {"status": "err", "param": "name", "message": e.msg}
    zone_name_str = str(zone_name.relativize(origin=dns.name.from_text('.')))
    try:
        name = dns.name.from_text(name, origin=zone_name)
    except dns.name.EmptyLabel as e:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {"status": "err", "param": "name", "message": e.msg}
    except dns.name.BadEscape as e:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {"status": "err", "param": "name", "message": e.msg}
    if not name.is_subdomain(zone_name):
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {"status": "err", "param": "name", "message": "name must be a subdomain of the zone"}

    if zone_name_str not in user['zones']:
        response.status_code = status.HTTP_403_FORBIDDEN
        return {"status": "err", "message": "Not authorized for this zone"}

    if not is_authorized(user, name, zone_name):
        response.status_code = status.HTTP_403_FORBIDDEN
        return {"status": "err", "message": "Not authorized for this name"}

    if ttl and ttl < 0:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {"status": "err", "param": "ttl", "message": "invalid ttl"} 

    try:
        rtype = dns.rdatatype.from_text(rtype)
    except dns.rdatatype.UnknownRdatatype as e:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {"status": "err", "param": "rtype", "message": e.msg}

    try:
        rdata = dns.rdata.from_text(dns.rdataclass.IN, rtype, value)
    except dns.exception.SyntaxError as e:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {"status": "err", "param": "value", "message": e.msg}

    filename = "{zone_name}.zone".format(zone_name=zone_name_str)
    filepath = Path(settings['zones_path'], filename)
    zone = dns.zone.from_file(str(filepath), origin=zone_name)
    rdataset = zone.find_rdataset(name, rtype, create=True)
    if not rdataset.issuperset(dns.rdataset.from_rdata(ttl or 0, rdata)):
        rdataset.add(rdata, ttl=ttl)
        upserial(zone)
        zone.to_file(str(filepath))

        if "reload_command" in settings:
            run(settings['reload_command'].replace("{zone_name}", zone_name_str), shell=True, check=True)

    return {"status": "OK"}


@app.put("/update/{zone_name}/delete", status_code=status.HTTP_200_OK)
async def delete(response: Response, zone_name: str, name: str, rtype: Optional[str] = None,
                 value: Optional[str] = None, credentials: HTTPBasicCredentials = Depends(security)):
    user = authenticate(credentials)
    try:
        zone_name = dns.name.from_text(zone_name)
    except dns.name.BadEscape as e:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {"status": "err", "param": "name", "message": e.msg}
    zone_name_str = str(zone_name.relativize(origin=dns.name.from_text('.')))
    try:
        name = dns.name.from_text(name, origin=zone_name)
    except dns.name.EmptyLabel as e:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {"status": "err", "param": "name", "message": e.msg}
    except dns.name.BadEscape as e:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {"status": "err", "param": "name", "message": e.msg}
    if not name.is_subdomain(zone_name):
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {"status": "err", "param": "name", "message": "name must be a subdomain of the zone"}

    if zone_name_str not in user['zones']:
        response.status_code = status.HTTP_403_FORBIDDEN
        return {"status": "err", "message": "Not authorized for this zone"} 

    if not is_authorized(user, name, zone_name):
        response.status_code = status.HTTP_403_FORBIDDEN
        return {"status": "err", "message": "Not authorized for this name"}

    try:
        rtype = dns.rdatatype.from_text(rtype)
    except dns.rdatatype.UnknownRdatatype as e:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {"status": "err", "param": "rtype", "message": e.msg}

    try:
        rdata = dns.rdata.from_text(dns.rdataclass.IN, rtype, value)
    except dns.exception.SyntaxError as e:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {"status": "err", "param": "value", "message": e.msg}

    filename = "{zone_name}.zone".format(zone_name=zone_name_str)
    filepath = Path(settings['zones_path'], filename)
    zone = dns.zone.from_file(str(filepath), origin=zone_name)

    if rtype is None:
        if value is None:
            zone.delete_node(name)
        else:
            response.status_code = status.HTTP_400_BAD_REQUEST
            return {"status": "err", "param": "rtype", "message": "rtype must be set when value is set"}
    else:
        if value is None:
            zone.delete_rdataset(name, rtype)
        else:
            rdataset = zone.find_rdataset(name, rtype, create=True)
            rdataset.discard(rdata)

    zone.to_file(str(filepath))

    if "reload_command" in settings:
        run(settings['reload_command'].replace("{zone_name}", zone_name_str), shell=True, check=True)
    
    return {"status": "OK"}
