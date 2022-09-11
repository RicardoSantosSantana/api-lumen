<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Laravel\Lumen\Routing\Controller as BaseController;
use App\Classes\ApiCall;

class ApiController extends BaseController
{

    public function index()
    {
       return view('vendor.swagger-lume.index');
    }


}
