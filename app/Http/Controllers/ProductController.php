<?php

namespace App\Http\Controllers;
use App\Http\Requests\ProductRequest;
use App\Models\product;
use Illuminate\Http\Request;

class ProductController extends Controller
{
    //

    public function index(){
        return product::all();
    }

    public function store(ProductRequest $request){
        $request->validate();
        return product::create($request->all());
    }

    public function show($id){
        return product::find($id);


    }

    public function update(Request $request, $id){
        $product = product::find($id);
        $product -> update($request->all());
        return $product;

    }

    public function destroy($id){
        return product::destroy($id);

    }

    public function search($name){
        return product::where('name','like', '%' .$name. '%')->get();

    }



}
