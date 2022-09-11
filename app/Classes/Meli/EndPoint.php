<?php

declare(strict_types=1);

namespace App\Classes\Meli;

use App\Classes\Meli\EndPointReturn;

class EndPoint
{
    static public function get_items_list_ids($user_id, $access_token): EndPointReturn
    {
        return new EndPointReturn("https://api.mercadolibre.com/users/" . $user_id . "/items/search?access_token=" . $access_token, "get", false);
    }

    static public function get_items_details($item_id): EndPointReturn
    {
        return new EndPointReturn("https://api.mercadolibre.com/items/" . $item_id, "get", false);
    }

    static public function get_items_description($item_id): EndPointReturn
    {
        return new EndPointReturn("https://api.mercadolibre.com/items/" . $item_id . "/description", "get", false);
    }

    static public function post_description($item_id): EndPointReturn
    {
        return new EndPointReturn("https://api.mercadolibre.com/items/$item_id/description", "post", true);
    }

    static public function create_item(): EndPointReturn
    {
        return new EndPointReturn("https://api.mercadolibre.com/items", "post", true);
    }

    static public function generate_token(): EndPointReturn
    {
        return new EndPointReturn("https://api.mercadolibre.com/oauth/token", "post", false);
    }

    static public function generate_refresh_token(): EndPointReturn
    {
        return new EndPointReturn("https://api.mercadolibre.com/oauth/token", "post", false);
    }

}
