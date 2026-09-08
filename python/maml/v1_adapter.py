"""JSONL conformance adapter executing the public MAML v1 implementation."""
import json
import sys
from . import v1


def _value(raw):
    return v1.CaptureValue(int(raw['value'],16),raw['kind'],raw['space'])


def _match(raw, schema):
    return v1.Match(int(raw['offset'],16),schema,{n:_value(v) for n,v in raw['captures'].items()})


def _encode(value):
    if value is None:
        return None
    return {'value':hex(value.value),'kind':value.kind,'space':value.space}


def _encode_match(match):
    return {'offset':hex(match.offset),'captures':{n:_encode(v) for n,v in match.captures.items()}}


def execute(request):
    if request['dialect'] != v1.DIALECT:
        raise ValueError('Unsupported dialect')
    try:
        op = request['operation']
        if op in {'compile','match_at'}:
            pattern = v1.Pattern(request['pattern'])
            schema = list(pattern.schema)
            if op == 'compile':
                return {'status':'ok','schema':schema}
            raw = request['image']
            image = v1.Image(bytes.fromhex(raw['bytes']),base=int(raw['base'],16),
                             pointer_map={int(m['value'],16):int(m['address'],16) for m in raw['pointer_map']})
            hit = pattern.match_at(image,int(request['start_offset'],16))
            if hit is None:
                return {'status':'no_match','schema':schema}
            return {'status':'ok','schema':schema,'match':_encode_match(hit)}
        if op == 'project':
            schema = request['schema']
            matches = [_match(m,schema) for m in request['matches']]
            values = v1.project(schema,matches,request['name'],unique=request['unique'])
            return {'status':'ok','values':[_encode(v) for v in values]}
        if op == 'lookup':
            match = _match(request['match'],request['schema'])
            return {'status':'ok','value':_encode(match.capture(request['name']))}
        if op == 'unique_matches':
            match = v1.unique_matches([_match(m,tuple(m['captures'])) for m in request['matches']])
            return {'status':'ok','match':_encode_match(match)}
        raise ValueError('Unknown operation: '+op)
    except v1.SchemaError as exc:
        return {'status':'schema_error','code':exc.code}
    except v1.CompileError as exc:
        return {'status':'compile_error','code':exc.code}
    except v1.CardinalityError:
        return {'status':'cardinality_error'}


def main():
    for line in sys.stdin:
        job=json.loads(line)
        print(json.dumps({'id':job['id'],'result':execute(job['request'])}),flush=True)


if __name__ == '__main__':
    main()
