<?php

use Illuminate\Support\Facades\Route;

/** @var \Laravel\Lumen\Routing\Router $router */

Route::group(['prefix' => 'api', 'middleware' => 'cors'], function () {



    Route::group(['middleware' => 'auth'], function () {

        Route::group(['prefix' => 'product'], function () {
            Route::get('/download', 'ProductController@download_save_products');
            Route::get('/', 'ProductController@index');
            Route::get('/{id}', 'ProductController@getProductId');
        });

        Route::group(['prefix' => 'meli'], function () {
            Route::post('/product/create',  '\App\Classes\Meli\Items@create');

            Route::post('/product/add_description',  '\App\Classes\Meli\Items@add_description');
            Route::post('/token/new',  '\App\Classes\Meli\Token_Meli@GenerateToken');
            Route::post('/token/refresh',  '\App\Classes\Meli\Token_Meli@GenerateRefreshToken');
        });
    });

    Route::group(['prefix' => 'user'], function () {
        Route::get('/profile/{id}', 'AuthController@profile');
        Route::post('/login', 'AuthController@login');
        Route::post('/register', 'AuthController@register');
    });
});
