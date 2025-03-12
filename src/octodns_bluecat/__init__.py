#
#
#

import re
import json
from collections import defaultdict
from logging import getLogger

from requests import Session

from octodns import __VERSION__ as octodns_version
from octodns.provider import ProviderException
from octodns.provider.base import BaseProvider
from octodns.record import Record
from octodns.idna import IdnaDict

# TODO: remove __VERSION__ with the next major version release
__VERSION__ = '0.0.7'
__version__ = __VERSION__

class BlueCatv2ClientException(ProviderException):
    pass


class BlueCatv2ClientNotFound(BlueCatv2ClientException):
    def __init__(self):
        super().__init__('Not Found')


class BlueCatv2ClientUnauthorized(BlueCatv2ClientException):
    def __init__(self):
        super().__init__('Unauthorized')


class BlueCatv2Client(object):

    def __init__(self, token, endpoint, cert, username, password, confname, viewname):
        self.log = getLogger(f'BlueCatv2Client: {endpoint}')
        self.log.debug(f'__init__ {confname} {viewname}')
        self.BASE=endpoint
        self.endpoint = endpoint
        sess = Session()
        self._sess = sess
        self._cert = cert
        self._zones = None

        mime_type = 'application/json'
        if username and password:
            payload = { 'username': username, 'password': password }
# Generate token
            resp = self._request(
                'POST',
                '/sessions',
                json=payload,
            )
            data = resp.json()
            token = data['basicAuthenticationCredentials']
            self.token = token
        sess.headers.update({'Authorization': f'Basic {token}'})
        sess.headers.update({'Content-Type': mime_type})
        sess.headers.update({'Accept': mime_type}) 
        sess.headers.update({'User-Agent': f'octodns/{octodns_version} octodns-bluecatv2/{__VERSION__}'})
        # change control header required for APIv2 for Integrity 9.5 and higher.
        sess.headers.update({'x-bcn-change-control-comment': f'making a change from octodns-bluecatv2'})

        self.conf_id = self._get_conf_id(confname)
        self.view_id = self._get_view_id(viewname, self.conf_id)
        self.ex_id = self.view_id + 1
        self.ex_id = self._get_exhost_zone_id(self.view_id)
        self.block_id = self._get_block_id(self.conf_id)

# Get Configuration ID
    def _get_conf_id(self, name):
        conf_id = 0
        resp = self._request(
            'GET',
            path='/configurations',
            params={'fields': 'name,id,type'},
        )
        data = resp.json()
        confs = data['data']
        for conf in confs:
            if conf['name'] == name:
                conf_id = conf['id']
                break
        self.log.debug(f'Conf ID: {conf_id}')
        return conf_id

# Get View ID
    def _get_view_id(self, name, cid):
        view_id = 0
        resp = self._request(
            'GET',
            path=f'/configurations/{cid}/views',
            params={'fields': 'name,id,type'},
        )
        data = resp.json()
        views = data['data']
        for view in views:
            if view['name'] == name and view['type'] == 'View':
                view_id = view['id']
                break
        self.log.debug(f'View ID: {view_id}')
        return view_id

# Get ExternalHostZone ID
    def _get_exhost_zone_id(self, view_id):
        resp = self._request(
            'GET',
            path=f'/views/{view_id}/zones',
            params = {'filter': "type:eq('ExternalHostsZone')"},
        )
        data = resp.json()
        ex_id = data['data'][0]['id']
        self.log.debug(f'ExZone ID: {ex_id}')
        return ex_id

# Get ExternalHostRecord Data
    def _get_ex_hosts(self):
        exhosts = dict()
        parms = {
            'fields': 'id,name,type',
            'filter': "type:eq('ExternalHostRecord')"
        }
        rrs = self._get_zone_rrs(self.ex_id, parms)
        for rr in rrs:
            exhosts[rr['name']] = rr['id']
        return exhosts

    def _get_zone_rrs(self, zid, parms={}):
        resp = self._request(
            'GET',
            path=f'/zones/{zid}/resourceRecords',
            params = parms, 
        )
        data = resp.json()['data']
        self.log.debug(f'_get_zone_rrs: {data}')
        return data

    def _is_ex_host(self, fqdn):
        exhosts = self._get_ex_hosts()
        if fqdn in exhosts:
            return exhosts[fqdn]
        else:
            return False

    def _create_ex_host(self, fqdn):
        ex_id = self._is_ex_host(fqdn)
        if ex_id:
            return ex_id
        else:
            payload = {
                'name': fqdn,
                'type': 'ExternalHostRecord',
            }
            resp = self._request(
                'POST',
                path=f'/zones/{self.ex_id}/resourceRecords',
                json = payload,
            )
            data = resp.json()
            return data['id']

# Get Block ID
    def _get_block_id(self, cid):
        blk_id = 0
        resp = self._request(
            'GET',
            path=f'/configurations/{cid}/blocks',
            params = {'fields': 'id', 'filter': "type:eq('IPv4Block')"},
        )
        data = resp.json()
        blk_id = data['data'][0]['id']
        self.log.debug(f'Block ID: {blk_id}')
        return blk_id

    def _request(self, method, path, params=None, json=None):
        url = f'https://{self.BASE}/api/v2{path}'
        self.log.debug(f'_request: {self._sess.headers}')
        self.log.debug(f'_request: params: {params}')
        self.log.debug(f'_request: json: {json}')
        resp = self._sess.request(method, url, params=params, json=json, verify=self._cert)
        self.log.debug(f'_request: {resp.url}')
        if resp.status_code == 400:
            self.log.debug(f'_request: resp.text {resp.text}')
            raise BlueCatv2ClientUnauthorized()
        if resp.status_code == 401:
            raise BlueCatv2ClientUnauthorized()
        if resp.status_code == 404:
            raise BlueCatv2ClientNotFound()
        resp.raise_for_status()
        return resp

    def _get_addresses_by_hostname_id(self, hostid):
        addrs = list()
        resp = self._request(
            'GET',
            f'/resourceRecords/{hostid}/addresses',
            params = { 'fields': 'address' },
        )
        data = resp.json()
        for add_dict in data['data']:
            addrs.append(add_dict['address'])
        return addrs

# Populate all the current zones and their IDs. Cache the data if needed`

    def _get_all_zones(self):
        if self._zones is None:
            params = {
                'limit': 5000,
                'fields': 'absoluteName, id',
                'filter': f"configuration.id:eq({self.conf_id}) and view.id:eq({self.view_id}) and type:eq('Zone')",
            }
            resp = self._request(
                'GET',
                path='/zones',
                params=params
            )
            data = resp.json()
            zones = data['data']
            self._zones = IdnaDict({f'{z["absoluteName"]}.': z['id'] for z in zones})
        return self._zones

    def _get_leaf_zones(self):
        leaf_zones = dict()
        all_zones = self._get_all_zones()
        for zone in all_zones:
            toks = zone.split('.')
            leaf = toks.pop(0)
            if re.match('[1-9][0-9][0-9]', leaf):
                leaf_zones[zone] = all_zones[zone]
        return leaf_zones

    def domains(self):
        return self._get_all_zones()

# returns the zone_id of a zone
    def domain(self, name):
        zones = self._get_all_zones()
        if name in zones:
            return zones[name]
        return False

    def _decouple(self, fqdn):
        toks = fqdn.split('.')
        name = toks.pop(0)
        zone = '.'.join(toks)
        zid = self.domain(zone)
        return(name, zone, zid)

    def domain_create(self, zone):
        pzid = self.view_id
        payload = {
            'type': 'Zone',
            'absoluteName': zone,
        }
        resp = self._request(
            'POST',
            path=f'/views/{pzid}/zones',
            json=payload
        )
        if resp.ok:
            data = resp.json()
            zid = data['id']
            self._zones[f'{zone}.'] = zid
            return zid
        else:
            self.log.debug(f'There was a problem creating subzone: {zone}')
            return False

    def domain_create_recursive(self, zone):
        zid = self.domain(zone)
        if zid:
            return zid
        else:
            (zname, subzone, subzid) = self._decouple(zone)
            pzid = self.domain_create_recursive(subzone)
            community = 'zones'
            if pzid == self.view_id:
                community = 'views'
            payload = {
                'type': 'Zone',
                'name': zname,
            }
            resp = self._request(
                'POST',
                path=f'/{community}/{pzid}/zones',
                json=payload
            )
            if resp.ok:
                data = resp.json()
                return data['id']
            else:
                self.log.debug(f'There was a problem creating subzone: {zone}')
                return False

# gets RRs of all kinds in a zone
    def records(self, zone_name):
        self.log.debug(f'getting rrs for {zone_name}')
        zone_id = self.domain(zone_name)
        path = f'/zones/{zone_id}/resourceRecords'
        resp = self._request(
                'GET',
                path = f'/zones/{zone_id}/resourceRecords',
        )
        data = resp.json()
        rrs = data['data']
        for rr in rrs:
            if rr['ttl'] is None:
                rr['ttl'] = 3600
        return rrs

    def record_create(self, zone_name, payload):
        zone_id = self.domain(zone_name)
        self._request(
            'POST',
            path=f'/zones/{zone_id}/resourceRecords',
            json=payload,
        )

    def record_delete(self, record_id):
        self.log.debug(f'deleting RR with RR id: {record_id}')
        self._request(
            'DELETE',
            path=f'/resourceRecords/{record_id}'
        )

class BlueCatv2Provider(BaseProvider):
    SUPPORTS_GEO = False
    SUPPORTS_DYNAMIC = False
    SUPPORTS_ROOT_NS = False
    SUPPORTS = set(('A', 'AAAA', 'CNAME', 'MX', 'TXT', 'Host'))

    def __init__(
            self,
            id,
            endpoint=None,
            username=None,
            password=None,
            confname=None,
            viewname=None,
            cert=None,
            token=None,
            *args,
            **kwargs
        ):
        self.log = getLogger(f'BlueCatv2Provider[{id}]')
        self.log.debug('__init__: id=%s, token=***', id)
        super().__init__(id, *args, **kwargs)
        self._client = BlueCatv2Client(token,endpoint,cert,username,password,confname,viewname)

        self._zone_records = {}

#
# Prepare Data for Yaml from BC
#
    def _data_for_GenericRecord(self, _type, records):
        return {
            'ttl': records[0]['ttl'],
            'type': 'A',
            'values': [r['rdata'] for r in records],
        }

    _data_for_A = _data_for_GenericRecord
    _data_for_AAAA = _data_for_GenericRecord

    def _data_for_Host(self, _type, records):
        values = self._client._get_addresses_by_hostname_id(records[0]['id'])
        return {
            'ttl': records[0]['ttl'],
            'type': 'A',
            'values': values,
        }

    def _data_for_CNAME(self, _type, records):
        record = records[0]
        self.log.debug(f'_data_for_CNAME: input data from Yaml: {record}')
        return {
            'ttl': record['ttl'],
            'type': _type,
            'value': f'{record["linkedRecord"]["name"]}.',
        }

    def _data_for_MX(self, _type, records):
        values = []
        for record in records:
            values.append(
                {
                    'preference': record['priority'],
                    'exchange': f'{record["data"]}.',
                }
            )
        return {'ttl': records[0]['ttl'], 'type': _type, 'values': values}


    def _data_for_TXT(self, _type, records):
        values = [value['text'].replace(';', '\\;') for value in records]
        return {
                'ttl': records[0]['ttl'],
                'type': _type,
                'values': values
        }

#
# gets the RRs for a zone 
# zone is a data structure
# calls _zone_records
#

    def zone_records(self, zone):
        self.log.debug(f'zone_records: zone: {zone.name}')
        self.log.debug(f'zone_records: {self._zone_records}')
        if zone.name not in self._zone_records:
            try:
                self._zone_records[zone.name] = self._client.records(zone.name)
            except BlueCatv2ClientNotFound:
                return []

        return self._zone_records[zone.name]

    def list_zones(self):
        self.log.debug('list_zones:')
        return sorted(self._client.domains().keys())

#
# takes data from BC via the v2 API to prepare it for the local/yaml destination
# calls zone_records to get the RRs on a zone by zone basis
# values end up in the YAML provider
#
    def populate(self, zone, target=False, lenient=False):
        self.log.debug(
            'populate: name=%s, target=%s, lenient=%s',
            zone.name,
            target,
            lenient,
        )

        values = defaultdict(lambda: defaultdict(list))
        for record in self.zone_records(zone):
            _type = self._mod_type(record)
            if _type not in self.SUPPORTS:
                self.log.warning(
                    'populate: skipping unsupported %s record', _type
                )
                continue
            values[record['name']][_type].append(record)
            self.log.debug(f'appending {record}')

        before = len(zone.records)
        for name, types in values.items():
            for _type, records in types.items():
                data_for = getattr(self, f'_data_for_{_type}')
                record = Record.new(
                    zone,
                    name,
                    data_for(_type, records),
                    source=self,
                    lenient=lenient,
                )
                zone.add_record(record, lenient=lenient)

        exists = zone.name in self._zone_records
        self.log.info(
            'populate:   found %s records, exists=%s',
            len(zone.records) - before,
            exists,
        )
        return exists

    def _mod_type(self, rr):
        bc_type = rr['type'][:-6]
        if bc_type == 'Generic':
            rr_type = rr['recordType']
        elif bc_type == 'Alias':
            rr_type = 'CNAME'
        else:
            rr_type = bc_type
        return rr_type

# getting data ready to add to BC
# A records are GenericRecords

    def _params_for_multiple(self, record):
        for value in record.values:
            yield {
                'name': record.name,
                'type': 'GenericRecord',
                'ttl': record.ttl,
                'recordType': record._type,
                'rdata': value,
            }

    _params_for_A = _params_for_multiple
    _params_for_AAAA = _params_for_multiple

    def _params_for_CNAME(self, record):
        ex_host = record.value[:-1]
        exhost_id = self._client._create_ex_host(ex_host)
        yield {
            'type': 'AliasRecord',
            'name': record.name,
            'ttl': record.ttl,
            'linkedRecord': {
                'id': exhost_id,
                'type': 'ExternalHostRecord',
            },
        }

    def _params_for_MX(self, record):
        for value in record.values:
            yield {
                'name': record.name,
                'ttl': record.ttl,
                'type': 'MXRecord',
                'linkedRecord': {
                    'id': record.id,
                    'type': 'HostRecord',
                },
                'priority': value.preference,
            }

    def _params_for_TXT(self, record):
        # BlueCatv2 doesn't want things escaped in values so we
        # have to strip them here and add them when going the other way
        for value in record.values:
            yield {
                'name': record.name,
                'ttl': record.ttl,
                'type': f'{record._type}Record',
                'text': value.replace('\\;', ';'),
            }

    def _apply_Create(self, change):
        new = change.new
        params_for = getattr(self, f'_params_for_{new._type}')
        for params in params_for(new):
            self.log.debug(f'_apply_Create: params: {params}')
            self._client.record_create(new.zone.name, params)

    def _apply_Update(self, change):
        self._apply_Delete(change)
        self._apply_Create(change)

    def _apply_Delete(self, change):
        existing = change.existing
        zone = existing.zone
        for record in self.zone_records(zone):
            rr_type = self._mod_type(record)
            self.log.debug(f'\nchecking if {record}\nneeds to be deleted for {existing.name} and {existing._type}\n')
            if ( existing.name == record['name'] and existing._type == rr_type ):
                self._client.record_delete(record['id'])

    def _apply(self, plan):
        desired = plan.desired
        changes = plan.changes
        self.log.debug(
            '_apply: zone=%s, len(changes)=%d', desired.name, len(changes)
        )

        domain_name = desired.name[:-1]
        if not self._client.domain(desired.name):
            self.log.debug('_apply:   no matching zone, creating domain')
            self._client.domain_create(domain_name)

        for change in changes:
            class_name = change.__class__.__name__
            getattr(self, f'_apply_{class_name}')(change)

        # Clear out the cache if any
        self._zone_records.pop(desired.name, None)
