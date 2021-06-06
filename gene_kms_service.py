#!/usr/bin/env python3.8
#coding=utf-8

import argparse
import json
import base64

from aliyunsdkcore.client import AcsClient


from aliyunsdkkms.request.v20160120 import ListKeysRequest
from aliyunsdkkms.request.v20160120 import ListKeyVersionsRequest
from aliyunsdkkms.request.v20160120 import DescribeKeyRequest
from aliyunsdkkms.request.v20160120 import DescribeKeyVersionRequest
from aliyunsdkkms.request.v20160120 import EncryptRequest
from aliyunsdkkms.request.v20160120 import DecryptRequest

class KeyMetadata(object):

    def __init__(self, value):
        self.creation_date = "" if "CreationDate" not in value else value.get("CreationDate")
        self.description = "" if "Description" not in value else value.get("Description")
        self.key_id = "" if "KeyId" not in value else value.get("KeyId")
        self.key_state = "" if "KeyState" not in value else value.get("KeyState")
        self.key_usage = "" if "KeyUsage" not in value else value.get("KeyUsage")
        self.key_spec = "" if "KeySpec" not in value else value.get("KeySpec")
        self.primary_key_version = "" if "PrimaryKeyVersion" not in value else value.get("PrimaryKeyVersion")
        self.delete_date = "" if "DeleteDate" not in value else value.get("DeleteDate")
        self.creator = "" if "Creator" not in value else value.get("Creator")
        self.arn = "" if "Arn" not in value else value.get("Arn")
        self.origin = "" if "Origin" not in value else value.get("Origin")
        self.material_expire_time = "" if "MaterialExpireTime" not in value else value.get("MaterialExpireTime")
        self.protection_level = "" if "ProtectionLevel" not in value else value.get("ProtectionLevel")
        self.last_rotation_date = "" if "LastRotationDate" not in value else value.get("LastRotationDate")
        self.automatic_rotation = "" if "AutomaticRotation" not in value else value.get("AutomaticRotation")

    def get_creation_date(self):
        return self.creation_date

    def set_creation_date(self, create_date):
        self.creation_date = create_date

    def get_description(self):
        return self.description

    def set_description(self, description):
        self.description = description

    def get_key_id(self):
        return self.key_id

    def set_key_id(self, key_id):
        self.key_id = key_id

    def get_key_state(self):
        return self.key_state

    def set_key_state(self, key_state):
        self.key_state = key_state

    def get_key_usage(self):
        return self.key_usage

    def set_key_usage(self, key_usage):
        self.key_usage = key_usage

    def get_key_spec(self):
        return self.key_spec

    def set_key_spec(self, key_spec):
        self.key_spec = key_spec

    def get_primary_key_version(self):
        return self.primary_key_version

    def set_primary_key_version(self, primary_key_version):
        self.primary_key_version = primary_key_version

    def get_delete_date(self):
        return self.delete_date

    def set_delete_date(self, delete_date):
        self.delete_date = delete_date

    def get_creator(self):
        return self.creator

    def set_creator(self, creator):
        self.creator = creator

    def get_arn(self):
        return self.arn

    def set_arn(self, arn):
        self.arn = arn

    def get_origin(self):
        return self.origin

    def set_origin(self, origin):
        self.origin = origin

    def get_material_expire_time(self):
        return self.material_expire_time

    def set_material_expire_time(self, material_expire_time):
        self.material_expire_time = material_expire_time

    def get_protection_level(self):
        return self.protection_level

    def set_protection_level(self, protection_level):
        self.protection_level = protection_level

    def get_last_rotation_date(self):
        return self.last_rotation_date

    def set_last_rotation_date(self, last_rotation_date):
        self.last_rotation_date = last_rotation_date

    def get_automatic_rotation(self):
        return self.automatic_rotation

    def set_automatic_rotation(self, automatic_rotation):
        self.automatic_rotation = automatic_rotation

class ListKeysResponse(object):

    def __init__(self, value):
        self.page_number = 0
        self.total_count = 0
        self.key_ids = []
        self.request_id = ""
        self.parse(value)

    def parse(self, value):
        response = json.loads(value)
        if ("Keys" in response) and ("Key" in response["Keys"]):
            for key in response["Keys"]["Key"]:
                if "KeyId" in key:
                    self.key_ids.append(key.get("KeyId"))
        if "PageNumber" in response:
            self.page_number = response["PageNumber"]
        if "TotalCount" in response:
            self.total_count = response["TotalCount"]
        if "RequestId" in response:
            self.request_id = response["RequestId"]

    def get_key_ids(self):
        return self.key_ids[:]

    def get_page_number(self):
        return self.page_number

    def get_total_count(self):
        return self.total_count

    def get_request_id(self):
        return self.request_id

def list_keys(acs_client):
    key_ids = []
    page_number = "1"
    page_size = "10"
    while True:
        request = ListKeysRequest.ListKeysRequest()
        request.set_accept_format('JSON')
        request.set_PageNumber(page_number)
        request.set_PageSize(page_size)
        response = ListKeysResponse(acs_client.do_action_with_exception(request))
        key_ids[len(key_ids):len(key_ids)] = response.get_key_ids()
        if response.get_page_number() * 10 >= response.get_total_count():
            break
        page_number = str(response.get_page_number() + 1)
    return key_ids

class DescribeKeyResponse(object):

    def __init__(self, value):
        self.key_metadata = None
        self.request_id = ""
        self.parse(value)

    def parse(self, value):
        response = json.loads(value)
        if "KeyMetadata" in response:
            self.key_metadata = KeyMetadata(response["KeyMetadata"])
        if "RequestId" in response:
            self.request_id = response["RequestId"]

    def get_key_metadata(self):
        return self.key_metadata

    def get_request_id(self):
        return self.request_id
def describe_key(acs_client, key_id):
    request = DescribeKeyRequest.DescribeKeyRequest()
    request.set_accept_format('JSON')
    request.set_KeyId(key_id)
    return DescribeKeyResponse(acs_client.do_action_with_exception(request))

class ListKeyVersionsResponse(object):

    def __init__(self, value):
        self.key_version_ids = []
        self.page_number = 0
        self.total_count = 0
        self.request_id = ""
        self.parse(value)

    def parse(self, value):
        response = json.loads(value)
        if ("KeyVersions" in response) and ("KeyVersion" in response["KeyVersions"]):
            for key_version in response["KeyVersions"]["KeyVersion"]:
                if "KeyVersionId" in key_version:
                    self.key_version_ids.append(key_version.get("KeyVersionId"))
        if "TotalCount" in response:
            self.page_number = response["TotalCount"]
        if "PageNumber" in response:
            self.total_count = response["PageNumber"]
        if "RequestId" in response:
            self.request_id = response["RequestId"]

    def get_key_version_ids(self):
        return self.key_version_ids[:]

    def get_page_number(self):
        return self.page_number

    def get_total_count(self):
        return self.total_count

    def get_request_id(self):
        return self.request_id

def list_key_versions(acs_client, key_id):
    key_version_ids = []
    page_number = "1"
    page_size = "10"
    while True:
        request = ListKeyVersionsRequest.ListKeyVersionsRequest()
        request.set_accept_format('JSON')
        request.set_KeyId(key_id)
        request.set_PageNumber(page_number)
        request.set_PageSize(page_size)
        response = ListKeyVersionsResponse(acs_client.do_action_with_exception(request))
        key_version_ids[len(key_version_ids):] = response.get_key_version_ids()
        if response.get_page_number() * 10 >= response.get_total_count():
            break
        page_number = str(response.get_page_number() + 1)
    return key_version_ids


class DescribeKeyVersionResponse(object):

    def __init__(self, value):
        self.request_id = ""
        self.key_id = ""
        self.key_version_id = ""
        self.creation_date = ""
        self.parse(value)

    def parse(self, value):
        response = json.loads(value)
        if "KeyVersion" in response:
            if "KeyVersionId" in response["KeyVersion"]:
                self.key_version_id = response["KeyVersion"]["KeyVersionId"]
            if "KeyId" in response["KeyVersion"]:
                self.key_id = response["KeyVersion"]["KeyId"]
            if "CreationDate" in response["KeyVersion"]:
                self.creation_date = response["KeyVersion"]["CreationDate"]
        if "RequestId" in response:
            self.request_id = response["RequestId"]

    def get_key_id(self):
        return self.key_id

    def get_key_version_id(self):
        return self.key_version_id

    def get_creation_date(self):
        return self.creation_date

    def get_request_id(self):
        return self.request_id

def describe_key_version(acs_client, key_id, key_version_id):
    request = DescribeKeyVersionRequest.DescribeKeyVersionRequest()
    request.set_accept_format('JSON')
    request.set_KeyId(key_id)
    request.set_KeyVersionId(key_version_id)
    return DescribeKeyVersionResponse(acs_client.do_action_with_exception(request))

class SymmetricEncryptResponse(object):

    def __init__(self, value):
        self.request_id = ""
        self.key_id = ""
        self.key_version_id = ""
        self.cipher_text_blob = ""
        self.parse(value)

    def parse(self, value):
        response = json.loads(value)
        if "RequestId" in response:
            self.request_id = response["RequestId"]
        if "KeyId" in response:
            self.key_id = response["KeyId"]
        if "KeyVersionId" in response:
            self.key_version_id = response["KeyVersionId"]
        if "CiphertextBlob" in response:
            self.cipher_text_blob = response["CiphertextBlob"]

    def get_request_id(self):
        return self.request_id

    def get_key_id(self):
        return self.key_id

    def get_key_version_id(self):
        return self.key_version_id

    def get_cipher_text_blob(self):
        return self.cipher_text_blob
class SymmetricDecryptResponse(object):

    def __init__(self, value):
        self.request_id = ""
        self.key_id = ""
        self.key_version_id = ""
        self.plain_text = ""
        self.parse(value)

    def parse(self, value):
        response = json.loads(value)
        if "RequestId" in response:
            self.request_id = response["RequestId"]
        if "KeyId" in response:
            self.key_id = response["KeyId"]
        if "KeyVersionId" in response:
            self.key_version_id = response["KeyVersionId"]
        if "Plaintext" in response:
            self.plain_text = response["Plaintext"]

    def get_request_id(self):
        return self.request_id

    def get_key_id(self):
        return self.key_id

    def get_key_version_id(self):
        return self.key_version_id

    def get_plain_text(self):
        return self.plain_text

def symmetric_encrypt(acs_client, key_id, key_version_id, message):
    request = EncryptRequest.EncryptRequest()
    request.set_accept_format('JSON')
    plain_text = base64.b64encode(message.encode('utf-8'))
    print(plain_text)
    request.set_KeyId(key_id)
    request.set_Plaintext(plain_text)
    response = SymmetricEncryptResponse(acs_client.do_action_with_exception(request))
    return base64.b64decode(response.get_cipher_text_blob())


def symmetric_decrypt(acs_client, key_id, key_version_id, cipher_blob):
    request = DecryptRequest.DecryptRequest()
    request.set_accept_format('JSON')
    cipher_text = base64.b64encode(cipher_blob)
    request.set_CiphertextBlob(cipher_text)
    response = SymmetricDecryptResponse(acs_client.do_action_with_exception(request))
    return base64.b64decode(response.get_plain_text())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ak', help='the access key id')
    parser.add_argument('--as', help='the access key secret')
    parser.add_argument('--region', default='cn-wulanchabu', help='the region id')
    parser.add_argument('--plain', default='', help='the text you want to encrypt')
    parser.add_argument('--cipher', default='', help='the text you want to decrypt')
    args = vars(parser.parse_args())

    client = AcsClient(args["ak"], args["as"], args["region"])

    key_ids = list_keys(client)
    # use the last CMK, and use the 1st key_version
    for key_id in key_ids:
        res = describe_key(client, key_id)
        key_metadata = res.get_key_metadata()
        key_id = key_metadata.get_key_id()
        key_version_ids = list_key_versions(client, key_id)
        key_version_id = key_version_ids[0]
        if not key_metadata.get_key_spec() == 'Aliyun_AES_256':
            public_key = get_public_key(client, key_id, key_version_ids[0])
            print(public_key)
    if args["plain"] != '':
        cipher_blob = symmetric_encrypt(client, key_id, key_version_id, args["plain"])
        print("the decode base64 cipher: [%s]" % cipher_blob)
    elif args["cipher"] != '':
        plain_text = symmetric_decrypt(client, key_id, key_version_id, str.encode(args["cipher"]))
        print("the decode base64 plain: [%s]" % plain_text.decode())
    else:
        print("please added --plain or --cipher argument")

    
if __name__ == '__main__':
    main()
    
