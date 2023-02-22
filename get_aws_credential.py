#THIS FILE IS RESPONSIBLE FOR GENERATE THE AUTHENTICATION ON AWS APIS FOR ROBIN TEST AUTOMATION
import requests
import json
import sys, os, base64, datetime, hashlib, hmac 

# *********************************************************
# *************  A M A Z O N   S I G N I N G  *************
# *************************begin***************************
# http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html

# General variables
CREDENTIALS = {
    'access_key':'',
    'secret_key':'',
    'session_token':''
}
t = datetime.datetime.utcnow()
amzdate = t.strftime('%Y%m%dT%H%M%SZ')
datestamp = t.strftime('%Y%m%d') # Date w/o time, used in credential scope
service = 'execute-api'
region = 'us-east-2'

def getSessionToken(environment):
    # environment = PROD or NONPROD
    cognitoUrl = 'https://cognito-identity.us-east-2.amazonaws.com/'
    if environment == "PROD":
        body = {"IdentityId": PROD_IDENTITY_ID}
    else:
        body = {"IdentityId": NONPROD_IDENTITY_ID}
    headers = {
        'content-type': 'application/x-amz-json-1.1',
        'x-amz-target': 'AWSCognitoIdentityService.GetCredentialsForIdentity'
    }
    response = requests.post(cognitoUrl, data=json.dumps(body), headers=headers)
    CREDENTIALS.update(access_key=response.json()["Credentials"]["AccessKeyId"])
    CREDENTIALS.update(secret_key=response.json()["Credentials"]["SecretKey"])
    CREDENTIALS.update(session_token=response.json()["Credentials"]["SessionToken"])

# Key derivation functions. See:
# http://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html#signature-v4-examples-python
def sign(key, msg):
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

def getSignatureKey(key, dateStamp, regionName, serviceName):
    kDate = sign(('AWS4' + key).encode('utf-8'), dateStamp)
    kRegion = sign(kDate, regionName)
    kService = sign(kRegion, serviceName)
    kSigning = sign(kService, 'aws4_request')
    return kSigning

def getAuthHeadersForAWSRequest(domain, method, endpoint, requestParameters):
    '''
    Returns the full header to be used on AWS request
    domain = PROD or NONPROD \n
    method = GET, POST \n
    endpoint = /stage-115/druglookup in example \n
    requestParameters = search-name=LIPITOR&client-ac-code=BRD01 in example
    '''

    if domain == 'PROD':
        host = PROD_DOMAIN + '.' + service + '.' + region + '.amazonaws.com'
    else:
        host = NONPROD_DOMAIN + '.' + service + '.' + region + '.amazonaws.com'
    
    # ************* TASK 1: CREATE A CANONICAL REQUEST *************
    # Step 1 is to define the verb (GET, POST, etc.)--already done through function parameter.
    # method = 'GET'

    # Step 2: Create canonical URI--the part of the URI from domain to query 
    # string (use '/' if no path)
    if endpoint == '':
        canonical_uri = '/'
    else:
        if method == 'POST':
            endpoint = endpoint + '/'
        canonical_uri = endpoint

    # Step 3: Create the canonical query string. In this example (a GET request),
    # request parameters are in the query string. Query string values must
    # be URL-encoded (space=%20). The parameters must be sorted by name.
    # For this example, the query string is pre-formatted in the request_parameters variable.
    #request_parameters = 'client-ac-code=BRD01&search-name=lipitor'
    canonical_querystring = requestParameters

    # Step 4: Create the canonical headers and signed headers. Header names
    # must be trimmed and lowercase, and sorted in code point order from
    # low to high. Note that there is a trailing \n.
    canonical_headers = 'host:' + host + '\n' + 'x-amz-date:' + amzdate

    # Step 5: Create the list of signed headers. This lists the headers
    # in the canonical_headers list, delimited with ";" and in alpha order.
    signed_headers = 'host;x-amz-date;x-amz-security-token'

    # Step 6: Create payload hash (hash of the request body content). For GET
    # requests, the payload is an empty string ("").
    payload_hash = hashlib.sha256(('').encode('utf-8')).hexdigest()
    
    # Step 7: Combine elements to create canonical request
    getSessionToken(domain)
    canonical_request = method +'\n'+ canonical_uri +'\n'+ canonical_querystring +'\n'+ canonical_headers +'\n'+ 'x-amz-security-token:'+ CREDENTIALS.get('session_token') +'\n\n'+ signed_headers +'\n'+ payload_hash
    #print("\nCanonical Request:\n--------------------------\n"+ canonical_request)
    
    # ************* TASK 2: CREATE THE STRING TO SIGN*************
    algorithm = 'AWS4-HMAC-SHA256'
    credential_scope = datestamp + '/' + region + '/' + service + '/' + 'aws4_request'
    string_to_sign = algorithm +'\n'+  amzdate +'\n'+  credential_scope +'\n'+  hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()
    #print("\nSTRING TO SIGN:\n--------------------------\n"+ string_to_sign)
    
    # ************* TASK 3: CALCULATE THE SIGNATURE *************
    signing_key = getSignatureKey(CREDENTIALS.get('secret_key'), datestamp, region, service)

    # Sign the string_to_sign using the signing_key
    signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()

    # ************* TASK 4: ADD SIGNING INFORMATION TO THE REQUEST *************
    authorization_header = algorithm +' '+ 'Credential=' + CREDENTIALS.get('access_key') +'/'+ credential_scope +', '+ 'SignedHeaders=' + signed_headers +', '+ 'Signature=' + signature
    headers = {'X-Amz-Security-Token':CREDENTIALS.get('session_token'), 'X-Amz-Date':amzdate, 'Authorization':authorization_header}
    print("\nAUTHORIZATION HEADERS:\n--------------------------\n")
    print(headers)
    return headers

# **************************end****************************
# *************  A M A Z O N   S I G N I N G  *************
# *********************************************************

#getAuthHeadersForAWSRequest('NONPROD','GET','/stage-115/druglookup','search-name=lipitor&client-ac-code=BRD01')

def printSessionAtributes(env):
    # This method prints access and secret key and session token to be used on Postman calls and 
    # make sure the getSessionToken(env) is working correctly.
    getSessionToken(env)
    print('Session token atributes for '+ env +':\n\n')
    print('\n- Access key: '+ CREDENTIALS.get('access_key'))
    print('\n- Secret key: '+ CREDENTIALS.get('secret_key'))
    print('\n- Session token: '+ CREDENTIALS.get('session_token'))

#printSessionAtributes('NONPROD')