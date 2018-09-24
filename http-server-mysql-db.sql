CREATE DATABASE dexter;

/* change the default password here and also in Laravel database config file */
CREATE USER 'dexteruser'@'localhost' IDENTIFIED BY '013579abcd';

GRANT ALL PRIVILEGES ON dexter.* TO 'dexteruser'@'localhost';

FLUSH PRIVILEGES;
