
var graphic_div = document.getElementById("graphic")
var info_div = document.getElementById("info")
var svg = d3.select(graphic_div).append("svg")

var forceX = d3.forceX(graphic_div.clientWidth / 2).strength(.2)
var forceY = d3.forceY(graphic_div.clientHeight / 2).strength(.2)

var simulation = d3.forceSimulation()
.force("link", d3.forceLink().id(function (d) {return d.id;}).distance(200).strength(1))
.force("charge", d3.forceManyBody())
.force("center", d3.forceCenter(graphic_div.clientWidth / 2, graphic_div.clientHeight / 2))
.force('x', forceX)
.force('y', forceY);

simulation.force("charge").strength(-500)
simulation.alpha(1).restart()

d3.json("/interfaces/nmapopenvas/demo", function (error, graph) {
    if (error) {
        d3.select("#name").html("No valid graph retrieved from endpoint.")
        d3.select("#desc").html("Ensure that you have run the Nmap app action 'graph from results' with the appropriate inputs; this interface will display the latest results from the output file of that action. You can also use the default 'WalkoffDemoGraph.json' in the Walkoff root directory if you have not yet run the aforementioned action")
    } else {
        update(graph.links, graph.nodes);
    }
});

function update(links, nodes) {
    link = svg.selectAll(".link")
    .data(links)
    .enter()
    .append("line")
    .attr("class", "link")

    node = svg.selectAll(".node")
    .data(nodes)
    .enter()
    .append("g")
    .attr("class", "node")
    .call(d3.drag()
        .on("start", dragstarted)
        .on("drag", dragged)
        .on("end", dragended)
        );

    node.append("circle")
    .attr("r", 10)
    .style("fill", function (d) {return fillNode(d);});

    node.append("title")
    .text(function (d) {return d.id;});

    node.append("text")
    .attr("dy", 4)
    .attr("dx", 12)
    .text(function (d) {return d.id;})

    node.on("click", function(d){

        info_text = "IP: " + d.id
        if ((d.hostnames != null) && (d.hostnames.length != 0)) {
			info_text += "</br>Hostname: " + d.hostnames
		}
        d3.select("#name").html(info_text)

        desc_text = ""
        if ((d.vulns != null) && (d.vulns.length != 0)) {
            desc_text += "<b>Select a result to view NVT data (in new window):<b>"
        }
        d3.select("#desc").html(desc_text)

        $('#table').bootstrapTable("destroy");
        new_data = d.vulns
        $('#table').bootstrapTable({data:new_data});

        $('#table').bootstrapTable('resetView',{
            height: newHeight()
        });
    });

    simulation
    .nodes(nodes)
    .on("tick", ticked);

    simulation.force("link")
    .links(links);
}

function ticked() {
    link
    .attr("x1", function (d) {return d.source.x;})
    .attr("y1", function (d) {return d.source.y;})
    .attr("x2", function (d) {return d.target.x;})
    .attr("y2", function (d) {return d.target.y;});

    node
    .attr("transform", function (d) {return "translate(" + d.x + ", " + d.y + ")";});
}

function dragstarted(d) {
    if (!d3.event.active) simulation.alphaTarget(0.3).restart()
        d.fx = d.x;
    d.fy = d.y;
}

function dragged(d) {
    d.fx = d3.event.x;
    d.fy = d3.event.y;
}

function dragended(d) {
    if (!d3.event.active) simulation.alphaTarget(0);
    d.fx = undefined;
    d.fy = undefined;
}

function fillNode(d) {
    c = "#808080" // grey - unscanned
    if (d.scanned == true && d.vulns.length == 0)
        c = "#ffffff" // white - no results
    else if (d.scanned == true && d.vulns.length > 0) {
        highest = 0
        for (vuln of d.vulns) {
            if (vuln.CVSS > highest)
                highest = vuln.CVSS
        }
        if (highest >= 9) {
            c = "#ff0000" //red - critical
        } else if (highest >= 7) {
            c = "#ff6600" //orange - high
        } else if (highest >= 4) {
            c = "#ffff00" //yellow - medium
        } else if (highest >= 1) {
            c = "#00cc00" //green - low
        } else if (highest >= 0) {
            c = "#ffffff" //white - info
        }
    }
    return c
}

function redraw(){

    // Extract the width and height that was computed by CSS.
    var width = graphic_div.clientWidth;
    var height = graphic_div.clientHeight;

    // Use the extracted size to set the size of an SVG element.
    svg
      .attr("width", width)
      .attr("height", height);

    simulation.force("center", d3.forceCenter(graphic_div.clientWidth / 2, graphic_div.clientHeight / 2));

    simulation.alphaTarget(0.3).restart();
    simulation.alphaTarget(0)

    $('#table').bootstrapTable('resetView',{
        height: newHeight()
    });
}

function newHeight() {
    return $("#info").height() - ($("#name").outerHeight(true) + $("#desc").outerHeight(true))
}

// Draw for the first time to initialize.
redraw();

// Redraw based on the new size whenever the browser window is resized.
window.addEventListener("resize", redraw);

$(document).ready(function() {
    $("#table").on("click-cell.bs.table", function (field, value, row, $el) {
        if ($el.OID != null) {
            $(function() {
                window.open("http://plugins.openvas.org/index.php?oid="+$el.OID)
            });
        }
    });
});

