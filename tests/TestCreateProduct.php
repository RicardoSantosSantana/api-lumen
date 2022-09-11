<?php

namespace Tests;


use Laravel\Lumen\Testing\DatabaseMigrations;
use Laravel\Lumen\Testing\DatabaseTransactions;
use App\Classes\ReturnUserToken;
use App\Models\Token;
use App\Models\User;
use stdClass;

class CreateProduct extends TestCase
{
    /**
     * A basic test example.
     *
     * @return void
     */


    public function testItems()
    {

        $pictures = [
            ["source" => "https://res.cloudinary.com/rssantan/image/upload/v1661210886/cld-sample-2.jpg"],
            ["source" => "https://res.cloudinary.com/rssantan/image/upload/v1661210887/cld-sample-4.jpg"],
            ["source" => "https://res.cloudinary.com/rssantan/image/upload/v1661210888/cld-sample-5.jpg"],
        ];


        $item = [
            "price" => 100,
            "title" => "Não ofertar - produto de teste",
            "description" => "Essa é a descrição do aplicativo que vendo",
            "available_quantity" => 1,
            "pictures" => $pictures,
            "currency_id" => "BRL",
            "category_id" => "MLB3530",
            "listing_type_id" => "free",
            "condition" => "new",
            "warranty" => "Garantia do vendedor",
            "warranty_quantity_time" => 6,
            "warranty_period" => "meses",
            "brand" => "HP",
            "model" => "2002-v"
        ];

        $this->assertNotEmpty($item);

        return $item;
    }

    /**
     * @depends testItems
     */
    public function test_create_product_on_api_meli(array $item)
    {

        $user = [
            "email" => "mirian@gmail.com",
            "client_id" => "client_id_ee528ba6-918f-4a32-9472-9089e7bc1742",
            "client_secret"=>"client_secret_84283077-ca7c-4fcf-841b-566406c3ff12",
            "grant_type"=> "credential"
        ];

        $url = '/api/login';
        $response = $this->call('POST', $url, $user);

        $endpoint = '/api/product/create';
        $response = $this->call('POST', $endpoint, $item);

        $response->assertJsonValidationErrors(['id'], $responseKey = null);
        $response->assertStatus(200);
    }
}
