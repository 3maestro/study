

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

}
