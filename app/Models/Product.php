<?php

namespace App\Models;

use App\Traits\Observers\ProductObserver;

use Illuminate\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Access\Authorizable as AuthorizableContract;
use Illuminate\Contracts\Auth\Authenticatable as AuthenticatableContract;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Laravel\Lumen\Auth\Authorizable;
use Tymon\JWTAuth\Contracts\JWTSubject;


class Product extends Model implements AuthenticatableContract, AuthorizableContract, JWTSubject
{
    use Authenticatable, Authorizable, HasFactory, ProductObserver;

    /**
     * The attributes that are mass assignable.
     *
     * @var string[]
     */


    public $incrementing = false;

    protected $fillable = [
        'id',
        'title',
        'site_id',
        'subtitle',
        'seller_id',
        'category_id',
        'official_store_id',
        'price',
        'base_price',
        'original_price',
        'currency_id',
        'initial_quantity',
        'available_quantity',
        'sold_quantity',
        'sale_terms',
        'buying_mode',
        'listing_type_id',
        'start_time',
        'stop_time',
        'condition',
        'permalink',
        'thumbnail_id',
        'thumbnail',
        'secure_thumbnail',
        'status',
        'warranty',
        'catalog_product_id',
        'domain_id',
        'health',
        'pictures',
        'description'
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
}
