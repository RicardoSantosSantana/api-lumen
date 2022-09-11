<?php

namespace App\Classes;

use App\Classes\Meli\{Token_Meli, EndPointReturn};

class  ApiCall
{

    private $token;

    public function __construct()
    {
        $this->token = Token_Meli::GetActiveToken();
    }

    private function Post($item, EndPointReturn $options)
    {


        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $options->url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HEADER,  false);

        if ($options->with_authorization_token) {
            curl_setopt($ch, CURLOPT_HTTPHEADER, ['Authorization: Bearer ' . $this->token->access_token]);
        }

        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($item));

        $output = curl_exec($ch);

        $err = curl_error($ch);

        $response = json_decode($output);

        curl_close($ch);

        if (isset($response->status) && $response->status != 200) {
            new \InvalidArgumentException(json_encode($response));
        }

        return $response;
    }

    private function Get($item, EndPointReturn $options)
    {


        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $options->url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HEADER,  false);

        if ($options->with_authorization_token) {
            curl_setopt($ch, CURLOPT_HTTPHEADER, ['Authorization: Bearer ' . $this->token->access_token]);
        }

        curl_setopt($ch, CURLOPT_HTTPGET, json_encode($item));

        $output = curl_exec($ch);

        $response = json_decode($output);

        curl_close($ch);

        if (isset($response->status) && $response->status != 200) {
            new \InvalidArgumentException(json_encode($response));
        }
        return $response;
    }

    public function Call($item, EndPointReturn $options)
    {
        return match ($options->method) {
            "post" => $this->Post($item, $options),
            "get" => $this->Get($item, $options)
        };
    }
}
