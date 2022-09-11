<?php

namespace App\Models;

use App\Traits\Observers\UserObserver;
use Illuminate\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Access\Authorizable as AuthorizableContract;
use Illuminate\Contracts\Auth\Authenticatable as AuthenticatableContract;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Laravel\Lumen\Auth\Authorizable;
use Illuminate\Support\Facades\Hash;
use Tymon\JWTAuth\Contracts\JWTSubject;

class User extends Model implements AuthenticatableContract, AuthorizableContract, JWTSubject
{
    use Authenticatable, Authorizable, HasFactory, UserObserver;

    /**
     * The attributes that are mass assignable.
     *
     * @var string[]
     */

    protected $fillable = [
        'id_social','provider','nickname', 'name', 'email','avatar_url', 'client_id', 'client_secret'
    ];

    /**
     * The attributes excluded from the model's JSON form.
     *
     * @var array
     */
    protected $hidden = [
        'password',
        'id'
    ];
    /**
     * The attributes excluded from the model's JSON form.
     *
     * @var string[]
     */

    public function getJWTIdentifier()
    {
        return $this->getKey();
    }

    public function getJWTCustomClaims()
    {
        return [];
    }

    public function setPasswordAttribute($val){
        $pass = Hash::make(($val));
        $this->attributes['password'] = $pass;
    }

    public function setClientIdAttribute($val){
        $this->attributes['client_id'] = 'client_id_'.$val;
    }

    public function setClientSecretAttribute($val){
        $this->attributes['client_secret'] = 'client_secret_'.$val;
    }
}
