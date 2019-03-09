## FTP Server

### Install the server

```sh
sudo apt install vsftpd
```

### Open `/etc/vsftpd.conf` and enable the file uploading

```
write_enable=YES
```

### Restart vsftpd

```
sudo systemctl restart vsftpd.service
```

---

## FTPs Server

### To configure FTPS, edit `/etc/vsftpd.conf` and at the bottom add

```
ssl_enable=YES
allow_anon_ssl=NO
force_local_data_ssl=YES
force_local_logins_ssl=YES
ssl_tlsv1=NO
ssl_sslv2=NO
ssl_sslv3=NO
ssl_ciphers=HIGH
```

### Notice the certificate and key related options

```
rsa_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
rsa_private_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
```

### Restart vsftpd

```sh
sudo systemctl restart vsftpd.service
```
