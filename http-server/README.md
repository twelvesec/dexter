## Laravel Framework

### Useful Links

* [Laravel setup on Ubuntu Server](https://github.com/SwiftOnLinux/SmokingLinuxEveryDay/blob/master/software/laravel-ubuntu-server-setup.md)
* [Laravel Installation](https://laravel.com/docs/5.7#installation)
* [API Authentication - passport](https://laravel.com/docs/5.7/passport#installation)

---

### Create a client

* client ID
* client secret

```
php artisan passport:client --password
```

---

### Create initial user

```bash
php artisan tinker
```

```php
$user = new App\User();
$user->name="Dexter";
$user->password = Hash::make('dexter_user_password');
$user->email = 'dexteruser@example.com';
$user->save();
```

---

### Retrieve auth token

**Using curl**

```bash
curl -x http://proxy:8080 http://example.com/oauth/token -d grant_type=password -d client_id=2 -d client_secret=aaaaaaabbbbbbbbbcccccccccdddddddeeeeeeee -d username='dexteruser@example.com' -d password='dexter_user_password' -d scope=*
```

```bash
curl -i -s -k  -X $'POST' \
    -H $'Host: example.com' -H $'User-Agent: curl/7.58.0' -H $'Accept: */*' -H $'Content-Length: 154' -H $'Content-Type: application/x-www-form-urlencoded' -H $'Connection: close' \
    --data-binary $'grant_type=password&client_id=2&client_secret=aaaaaaabbbbbbbbbcccccccccdddddddeeeeeeee&username=dexteruser@example.com&password=dexter_user_password&scope=*' \
    $'http://example.com/oauth/token'
```

**Raw request**

```
POST /oauth/token HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0
Accept: */*
Content-Length: 154
Content-Type: application/x-www-form-urlencoded
Connection: close

grant_type=password&client_id=2&client_secret=aaaaaaabbbbbbbbbcccccccccdddddddeeeeeeee&username=dexteruser@example.com&password=dexter_user_password&scope=*
```

---

### Log a client

**Using curl**

```
curl -i -s -k  -X $'POST' \
    -H $'Host: example.com' -H $'Accept: application/json' -H $'Content-Type: application/x-www-form-urlencoded' -H $'Authorization: Bearer [token]' -H $'Content-Length: 67' \
    --data-binary $'computername=maldevel_pc&os=Windows_10_amd64&username=maldevel_user' \
    $'http://example.com/api/computers'
```

**Raw request**

```
POST /api/computers HTTP/1.1
Host: example.com
User-Agent: curl/7.58.0
Accept: application/json
Content-Type: application/x-www-form-urlencoded
Authorization: Bearer [token]
Content-Length: 67

computername=maldevel_pc&os=Windows_10_amd64&username=maldevel_user
```

---
