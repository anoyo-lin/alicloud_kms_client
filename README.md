# alicloud kms service client

## prequiste
- access_key & access_secret of alicloud
- region of your kms CMK(customer master key)
- createKey(symmetric one), Alogrithm: aliyun_aes (provisioned the CMK)
- python interpreter installed

## usage
```bash
# cygwin on my side
# get apt-cyg script from internet
apt-cyg install python3-devel
pip install -r requirements.txt
chmod +x gene_kms_client.py
# encrypt
./gene_kms_client.py --ak "<access_key>" --as "<access_secret>" --plain "<plain_text_want_to_encrypt>"
# decrypt
./gene_kms_client.py --ak "<access_key>" --as "<access_secret>" --cipher "<cipher_text_want_to_decrypt>"
```

## in pipeline
```bash
python gene_kms_service.py --ak "LTAI5tFFLFbrcNXrmtxY****" --as "OnPihoOGFs8bBpsilXXPZM3rqf****" --cipher "153d66f3-28d5-4cb1-9fac-f75734c48abawAXXWi7U4IhqL8Z8nDOrUpEd6jBcTjINAAAAAAAAAABuetYaSIl9o6igxUfoY+2oOOGMx0i2XR5tGHzG"| sed -n 's#.*\[\([^]]*\)\].*#\1#p'
```