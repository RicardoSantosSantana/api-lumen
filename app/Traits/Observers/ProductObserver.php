<?php

namespace App\Traits\Observers;
use App\Models\Product;

trait ProductObserver
{
    protected static function boot()
    {

        parent::boot();

        static::retrieved(function (Product $product) {

        });

    }
}
