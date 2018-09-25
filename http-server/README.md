## Laravel Framework

### Useful Links

* [Laravel setup on Ubuntu Server](https://github.com/SwiftOnLinux/SmokingLinuxEveryDay/blob/master/software/laravel-ubuntu-server-setup.md)
* [Laravel Installation](https://laravel.com/docs/5.7#installation)
* [API AUthentication - passport](https://laravel.com/docs/5.7/passport#installation)

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

**Raw request**

```
POST /oauth/token HTTP/1.1
Host: 192.168.79.154
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0
Accept: */*
Content-Length: 154
Content-Type: application/x-www-form-urlencoded
Connection: close

grant_type=password&client_id=2&client_secret=aaaaaaabbbbbbbbbcccccccccdddddddeeeeeeee&username=dexteruser@example.com&password=dexter_user_password&scope=*
```

---
