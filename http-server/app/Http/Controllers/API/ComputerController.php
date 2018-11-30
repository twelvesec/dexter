<?php


namespace App\Http\Controllers\API;

use App\Http\Controllers\API\BaseController;
use Illuminate\Http\Request;
use App\Computer;
use Validator;

class ComputerController extends BaseController
{
    /*public function __construct()
    {
        parent::__construct();
    }*/

    public function index(Request $request)
    {
        $protocol = $request->input('protocol');

        $computers = Computer::where('protocol', $protocol)->get();

        return $this->sendResponse($computers->toArray(), 'Computers retrieved successfully.');
    }

    public function store(Request $request)
    {
        $input = $request->all();

        $validator = Validator::make($input, [
            'protocol' => 'required',
            'data' => 'required'
        ]);


        if($validator->fails())
        {
            return $this->sendError('Validation Error.', $validator->errors());
        }

        $computer = Computer::create([
            'protocol' => $request->protocol,
            'data' => $request->data,
            'user_id' => $request->user()->id
          ]);

        return $this->sendResponse($computer->toArray(), 'Computer created successfully.');
    }
}
