<?php

namespace App\Classes\Meli;

use Illuminate\Http\Request;

use App\Classes\ApiCall;
use App\Classes\Meli\{EndPoint, ItemsStruct, Common, Token_Meli};
use App\Models\Product;
use InvalidArgumentException;
use Illuminate\Support\Facades\Validator;

class Items
{

    use Common;
    private $token;
    private $rules =   [
        'brand' => 'required',
        'model' => 'required',
        'price' => 'required|numeric|min:10',
        'title' => 'required|string|min:20|max:60',
        'description' => 'required|string|min:30|max:4000',
        'available_quantity' => 'required|integer|min:1|max:1',
        'pictures' => 'required|array',
        'pictures.*.source' => 'required',
        'currency_id' => 'required|in:BRL',
        'category_id' => 'required|in:MLB3530',
        'listing_type_id' => 'required|in:gold_pro,gold_special,free',
        'condition' => 'required|in:not_specified,used,new',
        'warranty' => 'required',
        'warranty_quantity_time' => 'required|numeric|min:1|max:99',
        'warranty_period' => 'required|in:dias,meses,anos',
    ];
    private $message = [
        'brand.required'=>'The brand is required',
        'model.required'=>'The Model is required',
        'price.required'=>'The price is required',
        'price.min'=>'The min value is 10',
        'price.numeric'=>'The price must be numeric value',
        'title.required'=>'The title is required',
        'title.min'=>'The min characters is 20',
        'title.max'=>'The max characters is 60',
        'title.string'=>'The title must be string',

        'description.required'=>'The description is required',
        'description.min'=>'The min characters is 30',
        'description.max'=>'The max characters is 4000',
        'description.string'=>'The title must be string',

        'available_quantity.required' => 'Avalilable quantity is required',
        'available_quantity.integer' => 'Must be integer',
        'available_quantity.min' => 'The min value is 1 (one)',
        'available_quantity.max' => 'The max value is 1 (for test)',

        'currency_id.required' => 'Currency is required',
        'currency_id.in' => 'Currency must be BRL (for test)',


        'category_id.required' => 'Category id is required',
        'category_id.in' => 'For this demo the only allowed category is MLB3530',


        'listing_type_id.required'=>'The Listing type id is required',
        'listing_type_id.in' => 'The listing type id is invalid! - choose one: gold_pro, gold_special, free',

        'condition.required' => 'The condition is required',
        'condition.in' => 'The condition is invalid! - choose one: not_specified, used, new',

        'warranty.required' => 'The warranty is invalid! - choose one: Sem garantia, Garantia do vendedor, Garantia de fábrica',
        'pictures.required' => "Please inform pictures: example =  [ ['source' =>'link image' ], ['source' =>'link image' ] ]",
        'pictures.array' => "Picture must be array:  example =  [ ['source' =>'link image' ], ['source' =>'link image' ] ]",
        'pictures.*.source.required' => "Please inform pictures:  example =  [ ['source' =>'link image' ], ['source' =>'link image' ] ]",

        'warranty_quantity_time.required' => 'The Warranty quantity time is required',
        'warranty_quantity_time.numeric' => 'The Warranty quantity must be integer',
        'warranty_quantity_time.min' => 'The min value is 1',
        'warranty_quantity_time.max' => 'The max value is 99',

        'warranty_period.required' => 'The warranty period is required',
        'warranty_period.in' => 'The warranty period is invalid! - choose one: dias, meses, anos'
    ];

    public function formatItem($product)
    {
        try {

            $struct = new ItemsStruct(
                $product->id,
                $product->title,
                $product->site_id,
                $product->subtitle,
                $product->seller_id,
                $product->category_id,
                $product->official_store_id,
                $product->price,
                $product->base_price,
                $product->original_price,
                $product->currency_id,
                $product->initial_quantity,
                $product->available_quantity,
                $product->sold_quantity,
                json_encode($product->sale_terms),
                $product->buying_mode,
                $product->listing_type_id,
                $product->start_time,
                $product->stop_time,
                $product->condition,
                $product->permalink,
                $product->thumbnail_id,
                $product->thumbnail,
                $product->secure_thumbnail,
                $product->status,
                $product->warranty,
                $product->catalog_product_id,
                $product->domain_id,
                $product->health,
                json_encode($product->pictures),
                json_encode($product->description)
            );

            return (array)$struct;
        } catch (\Throwable $e) {
            return $e;
        }
    }

    public function get_items_id()
    {
        $token = Token_Meli::GetActiveToken();

        if(isset($token->error)){
            return $token;
        }

        $endpoint = EndPoint::get_items_list_ids($token->user_id, $token->access_token);

        $httpCall = new ApiCall;
        $response =  $httpCall->Call("", $endpoint);
        $items = [
            "seller_id"=>$response->seller_id,
            "items"=>$response->results
        ];

        return $items;
    }

    public function get_items_details($item_id)
    {

        $endpoint = EndPoint::get_items_details($item_id);

        $httpCall = new ApiCall;
        $response =  $httpCall->Call("", $endpoint);

        return $response;

    }

    public function get_items_description($item_id)
    {
        $endpoint = EndPoint::get_items_description($item_id);
        $httpCall = new ApiCall;

        $response =  $httpCall->Call("", $endpoint);

        if (isset($response->error)) {
            return  response()->json($response, $response->status);
        }

        return  $response;
    }

    public function add_description($item_id, $plain_text)
    {
        try {

            $endpoint = EndPoint::post_description($item_id);

            $description = ["plain_text" => $plain_text];

            $httpCall = new ApiCall;
            $response = $httpCall->Call($description, $endpoint);

            return $response;

        } catch (InvalidArgumentException $exception) {

            $error = json_decode($exception->getMessage());
            return response()->json($error, $error->status);
        }
    }

    public function create(Request $request)
    {


        $validator = Validator::make($request->all(), $this->rules, $this->message);

        if ($validator->fails()) {
            return $this->returnError($validator->errors(), 422);
        }

        try {

            $sale_terms = [
                ["id" => "WARRANTY_TYPE", "value_name" => $request->warranty],
                ["id" => "WARRANTY_TIME", "value_name" => $request->warranty_quantity_time . " " . $request->warranty_period]
            ];

            $attributes = [
                ["id" => "MODEL", "value_name" => $request->model],
                ["id" => "BRAND", "value_name" => $request->brand]
            ];

            $item = [
                "title" => $request->title,
                "category_id" => $request->category_id,
                "price" => $request->price,
                "currency_id" => $request->currency_id,
                "available_quantity" => $request->available_quantity,
                "buying_mode" => $request->buying_mode,
                "listing_type_id" => $request->listing_type_id,
                "condition" => $request->condition,
                "sale_terms" => $sale_terms,
                "pictures" => $request->pictures,
                "attributes" => $attributes
            ];

            $httpCall = new ApiCall;
            $endpoint = EndPoint::create_item();
            $response = $httpCall->Call($item, $endpoint);


            if (isset($response->error)) {
                return $response;
            }

            $item_id = $response->id;
            $response->description = $this->add_description($item_id, $request->description);

            if (isset($response->error)) {
                return $response;
            }

            $product = $this->formatItem($response);
            Product::create($product);
            return $product;

        } catch (\InvalidArgumentException $exception) {
            return response()->json($exception, 400);
        }
    }
}
