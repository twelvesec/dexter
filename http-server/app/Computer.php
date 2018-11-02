<?php

namespace App;

use Illuminate\Database\Eloquent\Model;

class Computer extends Model
{
    protected $fillable = ['user_id', 'uid', 'computername', 'os', 'username', 'localipaddress', 'physicaladdress'];

    public function user()
    {
      return $this->belongsTo(User::class);
    }
}
