"""Transparent synthetic access policy. No authentication or enforcement."""
import hashlib
import json
from dataclasses import dataclass

POLICY_VERSION='lab-v1'
ROLES={'engineer','analyst','clinician','auditor','external'}
PURPOSES={'operations','analytics','care','audit'}
CLASSIFICATIONS={'public','internal','sensitive','restricted','unknown'}
TRUST_LEVELS={'trusted','untrusted','unknown'}
PERMITTED_PURPOSE={'engineer':'operations','analyst':'analytics','clinician':'care','auditor':'audit'}

@dataclass(frozen=True)
class Decision:
    outcome: str
    reason: str


def evaluate(request):
    """Ordered policy: validation, purpose, sensitivity, channel, role checks."""
    required={'request_id','resource_id','role','purpose','classification','channel_trust','anomalous'}
    if not isinstance(request,dict) or not required.issubset(request):
        return Decision('review','invalid_schema')
    if not all(isinstance(request[k],str) and request[k].strip() for k in required-{'anomalous'}):
        return Decision('review','invalid_schema')
    if type(request['anomalous']) is not bool:
        return Decision('review','invalid_schema')
    if request['role'] not in ROLES or request['purpose'] not in PURPOSES or request['classification'] not in CLASSIFICATIONS or request['channel_trust'] not in TRUST_LEVELS:
        return Decision('review','unsupported_context')
    role=request['role'];classification=request['classification']
    if role!='external' and request['purpose']!=PERMITTED_PURPOSE[role]:
        return Decision('deny','role_purpose_mismatch')
    if classification=='unknown':
        return Decision('review','classification_unknown')
    if classification=='restricted':
        return Decision('deny','restricted_resource')
    if role=='external' and classification!='public':
        return Decision('deny','external_nonpublic')
    if request['channel_trust']=='untrusted' and classification!='public':
        return Decision('deny','untrusted_nonpublic_channel')
    if request['anomalous']:
        return Decision('review','anomalous_access')
    if request['channel_trust']=='unknown':
        return Decision('review','channel_trust_unknown')
    if classification=='sensitive' and role not in {'clinician','auditor'}:
        return Decision('deny','sensitive_role_not_allowed')
    return Decision('allow','context_matches_policy')


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()).hexdigest()


def audit_batch(requests):
    if not isinstance(requests,list):
        raise ValueError('Input must be a list of requests')
    seen=set();records=[];previous='0'*64
    for index,request in enumerate(requests):
        if not isinstance(request,dict) or not isinstance(request.get('request_id'),str) or not request['request_id'].strip():
            raise ValueError(f'Request {index}: nonempty string request_id required')
        if request['request_id'] in seen:
            raise ValueError(f'Duplicate request_id: {request["request_id"]}')
        seen.add(request['request_id'])
        decision=evaluate(request)
        record=dict(sequence=index,request_id=request['request_id'],resource_id=request.get('resource_id') if isinstance(request.get('resource_id'),str) else None,policy_version=POLICY_VERSION,outcome=decision.outcome,reason=decision.reason,previous_hash=previous)
        record['record_hash']=digest(record)
        previous=record['record_hash'];records.append(record)
    return records


def verify_chain(records):
    """Detect accidental/tampered records, not an attacker rewriting all hashes."""
    if not isinstance(records,list):return False
    previous='0'*64
    for index,record in enumerate(records):
        if not isinstance(record,dict):return False
        body={k:v for k,v in record.items() if k!='record_hash'}
        if record.get('sequence')!=index or record.get('previous_hash')!=previous or record.get('record_hash')!=digest(body):
            return False
        previous=record['record_hash']
    return True
