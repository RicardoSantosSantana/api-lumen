<?php

namespace App\Classes\Meli;

class ItemsStruct
{

    public function __construct(

        public $id,
        public $title,
        public $site_id,
        public $subtitle,
        public $seller_id,
        public $category_id,

        public $official_store_id,
        public $price,
        public $base_price,
        public $original_price,
        public $currency_id,

        public $initial_quantity,
        public $available_quantity,
        public $sold_quantity,
        public $sale_terms,
        public $buying_mode,

        public $listing_type_id,
        public $start_time,
        public $stop_time,
        public $condition,
        public $permalink,

        public $thumbnail_id,
        public $thumbnail,
        public $secure_thumbnail,
        public $status,
        public $warranty,

        public $catalog_product_id,
        public $domain_id,
        public $health,
        public $pictures,
        public $description
    ){ }

}
