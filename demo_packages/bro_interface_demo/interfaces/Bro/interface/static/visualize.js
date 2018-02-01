//window.onload = function() {setClicks()};
//
//function setClicks() {
//    var http_stats = ["status_code", "method", "user_agent", "id.orig_h", "host", "uri"]
//    var dns_stats = ["query", "qtype_name", "rcode_name", "qclass_name"]
//    for (let stat of http_stats) {
//        a = document.getElementById("http_"+stat)
//        alert(a.textContent)
//        a.onClick = function() {
//            alert("you clicked on " + stat)
//            getChart("http", stat)
//        }
//    }
//    for (let stat of dns_stats) {
//        document.getElementById("dns_"+stat).onClick = function() {
//            alert("you clicked on " + stat)
//            getChart("dns", stat)
//        }
//    }
//};

var chart1;
var chart2;
var buffer = 195;

function getChart(log, stat) {
    $('#c1title').text(`${log.toUpperCase()} log, requests per minute (${stat}):`);
    $('#c2title').text(`${log.toUpperCase()} log, ${stat} totals:`);
    $.ajax({
     'async': false,
     'type': "GET",
     'global': false,
         'headers': { "Authorization": 'Bearer ' + sessionStorage.getItem('access_token')},
         'url': `interfaces/Bro/demo?log=${log}&stat=${stat}`,
         'success': function(data) {
            //alert("good")
            var d = JSON.parse(data)
            if (d.columns != "Too many columns to display.") {
                drawLineChart(JSON.parse(data))
            } else {
                $('#chart1').text("Too many columns to display.");
            }
            drawPieChart(JSON.parse(data))
            reheight(buffer)
        },
        'error': function(e) {
            //alert("error")
            console.log(e.responseText)
            err = JSON.parse(e.responseText).error
            $('#chart1').text("Error: " + err);
            $('#chart2').text("Error: " + err);
        }
    });
}

function drawLineChart(data) {
    var strf = '%Y-%m-%d %H:%M:%S'
    chart1 = c3.generate({
        bindto: '#chart1',
        data: {
            x: 'index',
            xFormat: strf, 
            columns: data.columns
        },
        axis: {
            x: {
                type: 'timeseries',
                tick: {
                    rotate: 90,
                    format: strf
                }
            }
        }
    });
}

function drawPieChart(data) {
    chart2 = c3.generate({
        bindto: '#chart2',
        data: {
            columns: data.totals_col,
            type: 'pie'
        }
    });
}

window.onresize = function () {reheight(buffer)}
function reheight(n) {
    var x = window.innerHeight-n
    if (chart1 && chart2) {
        chart1.resize({height:x})
        chart2.resize({height:x})
    }
}