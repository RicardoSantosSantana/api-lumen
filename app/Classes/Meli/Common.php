<?php

namespace App\Classes\Meli;

use stdClass;

trait Common
{
    private $rulesCreateToken = [
        "code" => "required",
        "client_id" => "required",
        "client_secret" => "required",
        "redirect_uri" => "required"
    ];

    private $messagesCreateToken = [
        "code.required" => "To acquire new CODE, Open in Web Browser: https://code.ricardo.dev.br and inform your Client_ID",
        "client_id.required" => "The CLIENT_ID is provided when create a new app on Mercado Livre.",
        "client_secret.required" => "The CLIENT_SECRET is provided when create a new app on Mercado Livre.",
        "redirect_uri.required" => "The REDIRECT_URI must be the same configured in your application on Mercado Livre."
    ];

    private $rulesRefreshToken = [
        "client_id" => "required",
        "client_secret" => "required",
        "refresh_token" => "required"
    ];

    private $messagesRefreshToken = [
        "client_id.required" => "The CLIENT_ID is provided when create a new app on Mercado Livre.",
        "client_secret.required" => "The CLIENT_SECRET is provided when create a new app on Mercado Livre.",
        "refresh_token.required" => "The REFRESH_TOKEN is required, refresh token is created when a new token is generated."
    ];
    public function returnError($data, int $status)
    {
        $error = new stdClass;
        $error->error = $data;
        $error->status = $status;
        return response()->json($error, $status);
    }

    static public function returnStaticError($data, int $status)
    {
        $error = new stdClass;
        $error->error = $data;
        $error->status = $status;
        return $error;
    }

    static private function dateDiff($dateEnd): stdClass
    {

        $objReturn = new stdClass;

        $hour1 = 0;
        $hour2 = 0;
        $dateStart = date('Y-m-d H:i:s');

        $datetimeObj1 = new \DateTime($dateStart);
        $datetimeObj2 = new \DateTime($dateEnd);
        $interval = $datetimeObj1->diff($datetimeObj2);

        if ($interval->format('%a') > 0) {
            $hour1 = $interval->format('%a') * 24;
        }
        if ($interval->format('%h') > 0) {
            $hour2 = $interval->format('%h');
        }

        $objReturn->system_date = $datetimeObj1;
        $objReturn->token_updated_at = $datetimeObj2;
        $objReturn->diff_hours = $hour1 + $hour2;

        return $objReturn;
    }

    static private function envNewTokenParams(): array
    {
        return [
            "grant_type" => "authorization_code",
            "code" => env("CODE"),
            "client_id" => env("CLIENT_ID"),
            "client_secret" => env("CLIENT_SECRET"),
            "redirect_uri" => env("REDIRECT_URL")
        ];
    }

    static private function envRefreshTokenParams(): array
    {
        return [
            "grant_type" => "refresh_token",
            "client_id" => env("CLIENT_ID"),
            "client_secret" => env("CLIENT_SECRET")
        ];
    }
}
