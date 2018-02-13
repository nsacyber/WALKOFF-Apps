var chart1;
var chart2;
var buffer = 195;
var hiveScale = 1
var graphic_div;
var info_div;
var svg;
var bstable;
var hiddenLinks = false;
var tooltip;

$(document).ready(function() {
    graphic_div = document.getElementById("chart1")
    info_div = document.getElementById("chart2")
    $('#statsTable').css("display", "none")
    reheight(buffer)
});

function getMap(filter) {
    $('#c1title').text(`HTTP Request Map: ${filter}`);
    $('#c2title').text(`Click on a node to display information about it.`);
    $('#c1text').text(``);
    $('#c2text').text(``);
    if (chart1 && chart2) {
        chart1.destroy()
        chart2.destroy()
        chart1 = null
        chart2 = null
        $("#chart2").append(bstable)
    }
    let lc = document.getElementById("leftchart")
    let rc = document.getElementById("rightchart")
    if (!lc.classList.contains("col-sm-6")) {
        lc.classList.remove("col-sm-8")
        lc.classList.add("col-sm-6")
        rc.classList.remove("col-sm-4")
        rc.classList.add("col-sm-6")
    }

    $("#statsTable").css("display", "")


    d3.json("/interfaces/Bro/map", function (error, graph) {
        if (error) {
            d3v4.select("#c1title").html("No valid graph retrieved from endpoint.")
            d3v4.select("#c1text").html("Ensure that you have run the Bro app action 'make http netmap' after loading an appropriate HTTP log from Bro; this interface will display the latest results from the output file of that action.")
        } else {
            drawHiveChart(graph.links, graph.nodes);
        }
    });
}

function reorientById(nodes) {
    var r = {}
    for (node of nodes) {
        r[node.id] = node;
    }
    return r
}

function reorientByDistance(nodes) {
    var r = {}
    var i = 0
    Object.keys(nodes).sort().forEach(function(key) {
      r[key] = i;
      i++;
    });
    return r
}

function reorientByRequests(nodes) {
    var r = {}
    var i = 0
    Object.keys(nodes).sort(function (a, b) {
        return nodes[a].num_requests - nodes[b].num_requests
    }).forEach(function(key) {
      r[key] = i;
      i++;
    });
    return r
}

function getRequestRange(links) {
    var min = Number.MAX_SAFE_INTEGER,
        max = Number.MIN_SAFE_INTEGER;
    for (link of links) {
        if (link.num_requests < min)
            min = link.num_requests
        if (link.num_requests > max)
            max = link.num_requests
    }
    return [min, max]
}

function drawHiveChart(links, nodes) {

    //Adapted from https://bl.ocks.org/mbostock/2066415

    var nodesById = reorientById(nodes)

    var nodesByDistance = reorientByDistance(nodesById)

    var test = reorientByRequests(nodesById)

    var nodeRadius = 10

    var width = graphic_div.clientWidth,
        height = graphic_div.clientHeight,
        innerRadius = 1,
        outerRadius = nodes.length*nodeRadius*3;

    var requestRange = getRequestRange(links)

    var angle = d3.scale.ordinal().domain(d3.range(4)).rangePoints([0, 2 * Math.PI]),
        radius = d3.scale.linear().domain([0,Object.keys(test).length-1]).range([innerRadius, outerRadius]),
        color = d3.scale.category10().domain(d3.range(20)),
        thickness = d3.scale.linear().domain(requestRange).range([3, 13]);

    var dragNotClick = d3.behavior.drag()
    .on('dragstart', function () {
        d3.event.sourceEvent.stopPropagation();
    })

    svg = d3.select("#chart1")
     .append("div")
       .classed("svg-container", true)
     .append("svg")
       .attr("preserveAspectRatio", "xMidYMin meet")
       .attr("viewBox", `-${width/2} -${height/8} ${width*hiveScale} ${height*hiveScale}`)
       .classed("svg-content-responsive", true)
       .attr("id", "hivechart")
       .on("click", restoreLinks)
       .call(dragNotClick)


    svg.selectAll(".axis")
        .data([1, 2])
      .enter().append("line")
        .attr("class", "axis")
        .attr("transform", function(d) { return "rotate(" + degrees(angle(d)) + ")"; })
        .attr("x1", innerRadius)
        .attr("x2", outerRadius);

    svg.selectAll(".link")
        .data(links)
      .enter().append("path")
        .attr("class", "link")
        .attr("d", d3.hive.link()
        .angle(function(d) { return angle(nodesById[d].axis); })
        .radius(function(d) { return radius(test[d]); }))
        .style("stroke-width", function(d) { return thickness(d.num_requests) })
        .classed("malicious", function(d) { return d.mal_requests > 0 } )
        .on("mouseover", linkMouseOver)
        .on("mousemove", tooltipMove)
        .on("mouseout", linkMouseOut)
        .on("click", linkClick);

    var node = svg.selectAll(".node")
        .data(nodes)
      .enter().append("g")
      .attr("transform", function(d) { return "rotate(" + degrees(angle(d.axis)) + ")"; })
      .attr("dx", function(d) { return radius(test[d.id]); })

    node.append("circle")
        .attr("class", "node")
        //.attr("transform", function(d) { return "rotate(" + degrees(angle(d.axis)) + ")"; })
        .attr("cx", function(d) { return radius(test[d.id]); })
        .attr("r", nodeRadius)
        .style("fill", function(d) { return color(d.axis); })
        .on("mouseover", nodeMouseOver)
        .on("mousemove", tooltipMove)
        .on("mouseout", nodeMouseOut)
        .on("click", nodeClick);

    tooltip = d3.select("body").append("div")
        .attr("class", "myTooltip")
        .style("display", "none");

//    node.append("text")
//      .attr("dx", function(d) { return radius(test[d.id]); })
//      .style("text-anchor", "end")
//      .attr("transform", "rotate(90)")
//      .text(function(d) { return d.id });
//
//    svg.selectAll("text")
//        .style("text-anchor", "end")
//        .attr("transform", "rotate(-65)" );

    $(function() {
      panZoomInstance = svgPanZoom('#hivechart', {
        zoomEnabled: true,
        controlIconsEnabled: true,
        fit: true,
        center: true,
        minZoom: 0.1,
        increment: 0.5,
        transition: true
      });

      // zoom out
//      panZoomInstance.zoom(0.2)
    })

    reheight(buffer);

    function checkLink(d) {
        if (d.mal_requests > 0) {
            return "red"
        } else {
            return "grey"
        }
    }

    function radius(numNodes) {

    }

    function degrees(radians) {
      return radians / Math.PI * 180 - 90;
    }

    function tooltipMove() {
        tooltip
        .style("left", (d3.event.pageX+10) + "px")
        .style("top", (d3.event.pageY+10) + "px");
    }

    function linkMouseOver(d) {
        svg.selectAll(".link").classed("active", function(p) {
            return p === d;
        });
//        svg.selectAll(".node circle").classed("active", function(p) {
//            return p === d.source || p === d.target;
//        });
//        $('#c2title').text(`${d.source} to ${d.target}`);
//        $('#chart2').text(d.num_requests);
        tooltip.text(`${d.source} to ${d.target}`)
        tooltip.style("display", "inline");
    }

    function linkMouseOut(d) {
        setTimeout(function(){
            svg.selectAll(".link").classed("active", false)
        }, 100);
        tooltip.style("display", "none");
    }

    function linkClick(d) {

        temp = d3.event

        if (d3.event.defaultPrevented) return;
        if (hiddenLinks) {
            svg.selectAll(".link").classed("hidden", false);
        }
        svg.selectAll(".link").classed("hidden", function(p) {
            return (p.source != d.source || p.target != d.target);
        });

        d3.event.target.classList.add("active")

        l = nodesById[d.source].requests_by_host
        l2 = []
        for (line of l) {
            if (line.IP == d.target) {
                l2.push(line)
            }
        }

        $('#statsTable').bootstrapTable("destroy");
        $('#statsTable').bootstrapTable({data:l2});

        $('#c2title').text(`Selected Link: ${d.source} to ${d.target}`);

        reheight(buffer);
        setTimeout(function(){ hiddenLinks = true }, 5);
    }

    function nodeMouseOver(d) {
//        $('#c2title').text(d.id);
//        $('#chart2').prepend(`Number of Requests: ${d.num_requests}`);
//        reheight(buffer);
        tooltip.text(d.id)
        tooltip.style("display", "inline");
    }

    function nodeMouseOut(d) {
        tooltip.style("display", "none");
    }

    function nodeClick(d) {

        temp = d3.event

        if (d3.event.defaultPrevented) return;
        if (hiddenLinks) {
            svg.selectAll(".link").classed("hidden", false);
            svg.selectAll(".node").classed("active", false);
        }
        svg.selectAll(".link").classed("hidden", function(p) {
            return (p.source != d.id && p.target != d.id);
        });

        d3.event.target.classList.add("active")

        $('#statsTable').bootstrapTable("destroy");
        $('#statsTable').bootstrapTable({data:d.requests_by_host});

        var ip_type = ""
        if (d.axis == 1) {
            ip_type = "Source"
            $('#statsTable').bootstrapTable('showColumn', 'Hostname');
        } else {
            ip_type = "Destination"
            $('#statsTable').bootstrapTable('hideColumn', 'Hostname');

        }
        $('#c2title').text(`Selected Node: ${d.id} (${ip_type})`);

        reheight(buffer);
        setTimeout(function(){ hiddenLinks = true }, 5);

//        $('#statsTable').bootstrapTable('resetView',{
//            height: newHeight()
//        });

//        svg.selectAll(".node circle").classed("active", function(p) {
//            return p === d.source || p === d.target;
//        });
//        $('#c2title').text(`${d.source} to ${d.target}`);
//        $('#chart2').text(d.num_requests);
    }

    function restoreLinks(d) {

        if (d3.event.defaultPrevented) return;

        eType = d3.event.target.nodeName
        if (eType != "circle" && eType != "path") {
            svg.selectAll(".link").classed("hidden", false);
            svg.selectAll(".node").classed("active", false);
            hiddenLinks = false
        }
    }

}

function getChart(log, stat) {

    if (svg) {
        d3.select("svg").remove()
        svg = null
//        $("#statsTable").appendTo("body");
        $("#statsTable").css("display", "none")
        $('#statsTable').bootstrapTable("destroy");
    }

    bstable = $("#statsTable").get(0)

    let lc = document.getElementById("leftchart")
    let rc = document.getElementById("rightchart")
    if (!lc.classList.contains("col-sm-8")) {
        lc.classList.remove("col-sm-6")
        lc.classList.add("col-sm-8")
        rc.classList.remove("col-sm-6")
        rc.classList.add("col-sm-4")
    }

    $('#c1title').text(`${log.toUpperCase()} log, requests per minute (${stat}):`);
    $('#c2title').text(`${log.toUpperCase()} log, ${stat} totals:`);
    $('#c1text').text(``);
    $('#c2text').text(``);
    $.ajax({
     'async': false,
     'type': "GET",
     'global': false,
//         'headers': { "Authorization": 'Bearer ' + sessionStorage.getItem('access_token')},
         'url': `interfaces/Bro/demo?log=${log}&stat=${stat}`,
         'success': function(data) {
            //alert("good")
            var d = JSON.parse(data)
            if (d.columns != "Too many columns to display.") {
                drawLineChart(JSON.parse(data))
            } else {
                $('#c1text').text("Too many columns to display.");
            }
            drawPieChart(JSON.parse(data))
        },
        'error': function(e) {
            //alert("error")
            console.log(e.responseText)
            err = JSON.parse(e.responseText).error
            $('#c1text').text("Error: " + err);
            $('#c2text').text("Error: " + err);
        }
    });

    reheight(buffer);
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
    var c1h = x-$('#c1text').outerHeight(true);
    var c2h = x-$('#c2text').outerHeight(true);

//    if (svg) {
//        c2h -= $('#statsTable').outerHeight(true);
//    }

    document.getElementById("chart1").style.height = c1h + "px"
    document.getElementById("chart2").style.height = c2h + "px"

    document.getElementById("chart1").style.maxHeight = ""
    document.getElementById("chart2").style.maxHeight = ""
    if (chart1 && chart2) {
        chart1.resize({height:c1h})
        chart2.resize({height:c2h})
    }

    if (svg) {
        var h = parseInt(document.getElementById("chart2").style.height
                                                          .replace("px", ""))
        $('#statsTable').bootstrapTable('resetView',{
            height: h
        });
    }
//    if (svg) {
//        var width = graphic_div.clientWidth;
//        var height = graphic_div.clientHeight;
//        svg.attr("viewBox", `-${width/2} -${height/8} ${width*hiveScale} ${height*hiveScale}`)
//    }
}

function malList(index, row) {
    var html = [];
    incidents = row.malreqs
    if (incidents.length == 0) {
        return "No malicious HTTP requests detected (or request is internal)."
    }
    for (row of incidents) {
        var date = new Date(row.context.Timestamp*1000)
        html.push(`<p><b><u>Alerts:</u></b><br><b>IP: </b>${row.alerts.ip}<br><b>Domain: </b>${row.alerts.domain}<br></p><p><b><u>Context:</u></b><br><b>Bro Log UID: </b>${row.context.uid}<br><b>Timestamp: </b>${date}<br><b>Method: </b>${row.context.Method}<br><b>Status: </b>${row.context.Status}<br><b>URI: </b>${row.context.URI}<br></p><hr>`)
    }
    html[html.length-1] = html[html.length-1].replace("<hr>", "")
//    row.malreqs
//    $.each(row, function (key, value) {
//        if (key == "Mal Reqs") {
//            $.each(value, function (value) {
//                html.push('<p><b>' + key + ':</b> ' + value + '</p>');
//            })
//        }
//    });
    return html;
}