
$(document).ready(function(){
    console.log("===========ready===========");
})
var config = {
    t : v => {
        console.log("t fun start!!!");
        var total = 0;
        var a = 10;
        var b = a + 1;

        total = (a + b + b) * v;
        return total;
    },
    val : {
        obj : {
            dit : a => a * 21,
            total : ""
        },
        vl : "123"
    },
    
    api:""

}

var api = function() {
    var _callback="";
    function testFun(a,b,_callback){
        _callback = _callback;
        console.log("testFun call ....");
        console.log(a);
        console.log(b);
    }

    return {
        testFun : testFun

    }
}

config.api = new api();
