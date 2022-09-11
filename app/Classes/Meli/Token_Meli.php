<?php

namespace App\Classes\Meli;

use App\Classes\ApiCall;
use App\Classes\Meli\{EndPointReturn, Common};
use App\Models\Token;
use \Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class Token_Meli
{
    use Common;

    static public function GetActiveToken()
    {
        $endpoint = EndPoint::generate_refresh_token();

        $validade_token_in_hour = 5;

        $token = Token::latest()->first();

        if (!$token) {
            return self::returnStaticError("Invalid Token, please generate new Meli Token", 422);
        }

        $data = self::dateDiff($token->updated_at);

        if ((int)$data->diff_hours >= (int)$validade_token_in_hour) {

            $data = self::envRefreshTokenParams();
            $data["refresh_token"] = $token->refresh_token;

            return  self::Exec($data, $endpoint);
        }

        return $token;
    }
    static private function Exec($data, EndPointReturn $endpoint)
    {

        $httpCall = new ApiCall;
        $response = $httpCall->Call($data, $endpoint);

        if (isset($response->error)) {
            return self::returnStaticError($response, $response->status);
        }

        Token::create((array)$response);
        return  $response;
    }
    private function dataRefreshToken(Request $req)
    {

        $data = [];

        $token = self::GetActiveToken();
        $params = $this->envRefreshTokenParams();

        if ($token->error) {
            return (array)$token;
        }

        if (count($req->all()) > 0) {

            $req->merge(["grant_type" => "refresh_token"]);
            return [...$req->all()];
        }

        $data = [...$params];
        $data["refresh_token"] = $token->refresh_token;
        return   $data;
    }


    public function GenerateRefreshToken(Request $req)
    {

        $endpoint = EndPoint::generate_refresh_token();

        $data = $this->dataRefreshToken($req);

        if (isset($data["error"])) {
            return $this->returnError($data, 422);
        }

        $validator = Validator::make($data, $this->rulesRefreshToken, $this->messagesRefreshToken);

        if ($validator->fails()) {
            return $this->returnError($validator->errors(), 422);
        }

        $refresh = self::Exec($data, $endpoint);
        return response()->json($refresh, 200);
    }

    public function GenerateToken(Request $req)
    {

       $data=[];
        if (count($req->all()) > 0) {
            $req->merge(["grant_type"=>"authorization_code",...$req->all()]);
            $data = $req->all();
        } else {
            $data = [...self::envNewTokenParams()];
        }

        $validator = Validator::make($data, $this->rulesCreateToken, $this->messagesCreateToken);

        if ($validator->fails()) {
            return $this->returnError($validator->errors(), 422);
        }

        $endpoint = EndPoint::generate_token();

        //return json_encode($endpoint);
        //return json_encode($data);

        $token = self::Exec($data, $endpoint);

        return json_encode($token);
        return response()->json($token, 200);
    }
}
