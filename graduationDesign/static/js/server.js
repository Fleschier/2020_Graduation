
$(document).ready(function(){
    var ws 
    var blockIP = document.getElementById("blockIP")
    var currentInfo = document.getElementById("currentInfo")
    //var flow = document.getElementById("flow")
    var ifcontinue = true
    var ipv4_data = [0,0,0,0,0,0,0,0,0,0,0] //默认长度11
    var ipv6_data = [0,0,0,0,0,0,0,0,0,0,0]
    drawChart(ipv4_data, ipv6_data) //默认先画一个空的图
    

    $("#startListening_button").click(function(){
        ifcontinue = true
        ws = new WebSocket("ws://127.0.0.1:8888/listen")
        this.setAttribute("style","margin-top:10px;margin-bottom: 10px;visibility: hidden;")
        document.getElementById("stopListening_button").setAttribute("style","margin-top:10px;margin-bottom: 10px;visibility: visible;")
        document.getElementById("background_button").setAttribute("style","margin-top:10px;margin-bottom: 10px;visibility: visible;")
        openWS(blockIP, currentInfo, ws, ifcontinue,ipv4_data, ipv6_data)
        sendMessage("start", ws)
        //drawChart()
    })

    $("#stopListening_button").click(function(){
        ifcontinue = false
        this.setAttribute("style","margin-top:10px;margin-bottom: 10px;visibility: hidden;")
        document.getElementById("startListening_button").setAttribute("style","margin-top:10px;margin-bottom: 10px;visibility: visible;")
        document.getElementById("background_button").setAttribute("style","margin-top:10px;margin-bottom: 10px;visibility: hidden;")
        openWS(blockIP, currentInfo, ws, ifcontinue,ipv4_data, ipv6_data)
        sendMessage("stop", ws)
    })
})


function drawChart(ipv4_data, ipv6_data){
    // chart图表
    //var ctx = document.getElementById("myChart").getContext("2d");
    //var myLineChart = new Chart(ctx).Line(data, options); //报错，原来是说明文档过期了。看的是中文的，垃圾！！！淦
    var options = {
        scaleShowGridLines : false,     //是否显示网格线
        responsive: true,
        // Boolean - Whether to animate the chart
        animation: true,
        // Number - Number of animation steps
        animationSteps: 1,//本来是60
        title: {
            display: true,
            text: 'Ipv4和Ipv6 TCP流量统计'
        },
        tooltips: {
            mode: 'index',
            intersect: false,
        },
        hover: {
            mode: 'nearest',
            intersect: true
        },
        scales: {
            xAxes: [{
                display: true,
                scaleLabel: {
                    display: true,
                    labelString: 'Time/second'
                }
            }],
            yAxes: [{
                display: true,
                scaleLabel: {
                    display: true,
                    labelString: 'Speed/segmentation'
                }
            }]
        }
    }
    var data = {
        labels: ['0', '2', '4', '6', '8', '10', '12', '14', '16', '18', '20'],
        datasets: [{
            label: 'Ipv4',
            // data: [12, 19, 3, 5, 2, 3],
            data: ipv4_data,
            backgroundColor: [
                // 'rgba(255, 99, 132, 0.2)',
                // 'rgba(54, 162, 235, 0.2)',
                // 'rgba(255, 206, 86, 0.2)',
                 'rgba(75, 192, 192, 0.2)',
                // 'rgba(153, 102, 255, 0.2)',
                // 'rgba(255, 159, 64, 0.2)'
            ],
            borderColor: [
                // 'rgba(255, 99, 132, 1)',
                // 'rgba(54, 162, 235, 1)',
                // 'rgba(255, 206, 86, 1)',
                'rgba(75, 192, 192, 1)',
                // 'rgba(153, 102, 255, 1)',
                // 'rgba(255, 159, 64, 1)'
            ],
            borderWidth: 1
        },
        {
            label: 'Ipv6',
            // data: [12, 19, 3, 5, 2, 3],
            data: ipv6_data,
            backgroundColor: [
                'rgba(153, 102, 255, 0.2)',
                // 'rgba(255, 159, 64, 0.2)'
            ],
            borderColor: [
                'rgba(153, 102, 255, 1)',
                // 'rgba(255, 159, 64, 1)'
            ],
            borderWidth: 1
        }]
    }
    var ctx = document.getElementById('myChart').getContext('2d');
    var myChart = new Chart(ctx, {
        type: 'line',
        data: data,
        options: options
    }); 

}


// key function
function openWS(blockIP, currentInfo, ws, ifcontinue,ipv4_data, ipv6_data) {
  
    ws.onopen = function(e){    //连接成功后的回调函数
      
    }
    ws.onmessage = function(e) {  //收到服务器数据之后的回调函数
        var data = JSON.parse(e.data)
        if(data.type == "clear"){
            blockIP.innerHTML = ''
            currentInfo.innerHTML = ''
            //flow.innerHTML = ''   //流量统计另行刷新
        }
        if(data.type == "continue"){    //是否继续
            if(ifcontinue == true){
                sendMessage("start", ws)
            }
            else{
                sendMessage("stop", ws)
            }
        }
        if(data.type == "blockIP"){
            blockIP.appendChild(createChatEntry(data.message))
            scrollToBottom("blockIP")
        }
        if(data.type == "currentInfo"){
            currentInfo.appendChild(createChatEntry(data.message))
            scrollToBottom("currentInfo")
        }
        // 数组处理 队列方法是First-In-First-Out先进先出
        // unshift()  从数组前端添加
        // shift()    从数组前端移除
        // 栈方法是指Last-In-First-Out后进先出
        // push() 从数组末尾添加
        // pop()  从数组末尾移除
        if(data.type == "current_flow"){
            for(i = 0, len = ipv4_data.length; i < len - 1; i++){
                ipv4_data[i] = ipv4_data[i+1]
                ipv6_data[i] = ipv6_data[i+1]
            }
            ipv4_data[len - 1] = Number(data.message["Ipv4"])
            ipv6_data[len - 1] = Number(data.message["Ipv6"])
            console.log(ipv4_data)
            console.log(ipv6_data)
            drawChart(ipv4_data, ipv6_data)
        }
        if(data.type == "total_flow"){
            // 以太网的MTU一般为1500字节。
            console.log(data.message)
            document.getElementById("total_count").innerHTML = (Number(data.message)*1500/1024).toString()
        }
    }
    ws.onclose = function(e) {
        //messageContainer.appendChild(createChatEntry("======================================"))
        //window.setTimeout("logout();",5000)
    }
    ws.onerror = function(e) {
      console.log('Error occured: ' + e.data)
    }
  
}

//消息更新
function createChatEntry(message) {
    var entry = document.createElement("div")
    //entry.setAttribute("id","chat_list")
    
    var dom_uname = document.createElement("span")
    entry.appendChild(dom_uname)
    var sys_msg = document.createElement("span")
    sys_msg.setAttribute("class","sys_message")
    sys_msg.innerHTML = message
    entry.appendChild(sys_msg)

    return entry
}
//让浏览器滚动条保持在最低部
function scrollToBottom(ID){
    // w.scrollTo(0, window.getElementById("chatbox").innerHeight);
    var obj = document.getElementById(ID);
    obj.scrollTop = obj.scrollHeight;
    //清除消息框
    //document.getElementById("message").value="";
}
function sendMessage(Type, ws) {      //发送数据到后端处理
    var data = { 
        type: Type,
        data:"None",
    }
    sendMsg(JSON.stringify(data), ws)
}

  
//解决Tornado WebSockets - InvalidStateError “Still in CONNECTING State”
function sendMsg(msg, ws) {
    waitForSocketConnection(ws, function() {
        ws.send(msg);
    })
}

function waitForSocketConnection(socket, callback){   //等待连接建立再开始发送
    setTimeout(
        function(){
            if (socket.readyState === 1) {
                if(callback !== undefined){
                    callback();
                }
                return
            } else {
                waitForSocketConnection(socket,callback);
            }
        }, 50)
}
