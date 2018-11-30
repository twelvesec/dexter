<?php

namespace App;

use Illuminate\Database\Eloquent\Model;

class Computer extends Model
{
    protected $fillable = ['user_id', 'protocol', 'data'];

    public function user()
    {
      return $this->belongsTo(User::class);
    }
}
