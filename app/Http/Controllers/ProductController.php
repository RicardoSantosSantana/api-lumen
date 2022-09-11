<?php

namespace App\Http\Controllers;

use App\Models\Product;

use App\Classes\Meli\Items;
use Laravel\Lumen\Routing\Controller as BaseController;
use App\Traits\ApiResponser;
use Illuminate\Support\Facades\DB;

class ProductController extends BaseController
{
    use ApiResponser;

    public function index()
    {
        return $this->successResponse(Product::all());
    }

    public function getProductId($id)
    {


        if ($product = Product::where('id', $id)->first()) {
            return response()->json($product, 200);
        }

        return response()->json(['error' => 'product not found'], 422);
    }

    public function download_save_products()
    {

        $transaction =   DB::transaction(function () {

            $items = new Items;

            $id_items = (object)$items->get_items_id();

            $data = [];

            foreach ($id_items->items as $i => $item) {
                $detail = $items->get_items_details($item);
                $detail->description  = $items->get_items_description($item);
                $product = $items->formatItem($detail);
                $data [$i] = (array)$product;
            }

            DB::table('products')->delete();
            DB::table('products')->insert($data);

            return response()->json(["message" => "products save on database","data"=>$data], 200);
        });

        return $transaction;
    }
}
