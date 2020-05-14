
$(document).ready(function(){
    $("#connect_button").click(function(){
        // $("#connect_button").modal("hide") //点击完后关闭遮罩层，show则为显示
        // 改为在页面中实现更为简单：在button标签中添加属性data-dismiss="modal"
        // 即如果你的modal弹窗里面加上这个按钮，那么点击则会关闭当前弹窗
        var wifiname = document.getElementById("wifiname").value
        var wifikey = document.getElementById("wifikey").value
        var Data = {
            "wifiname":wifiname,
            "wifikey":wifikey
        }
        $.ajax({
            type:"post",
            url:"/connect",
            data:Data,
            success:function(info){
                alert(info)
            },
            error:function(){
                alert("error!")
            }
        })
    })

    var messageContainer = document.getElementById("chatbox")

    // 这里的按钮由于是动态生成且不唯一，所以用类名来获取，无法用id
    $(".secure_check_button").click(function(){

        var ws = new WebSocket("ws://127.0.0.1:8888/secure_check")
        // 清除缓存
        clearContent('chatbox')
        //获取当前wifi。其值保存在button的value中
        var current_wifi = this.value
        openWS(messageContainer, ws)  
        reg(current_wifi, ws)

    })

    $("#checkall_button").click(function(){
        var ws = new WebSocket("ws://127.0.0.1:8888/secure_check")
        openWS(messageContainer, ws)  
        sendMessage("checkall", ws)
    })

    $("#basecheck_button").click(function(){
        var ws = new WebSocket("ws://127.0.0.1:8888/secure_check")
        openWS(messageContainer, ws)  
        sendMessage("basecheck", ws)
    })

    $("#keycheck_button").click(function(){
        var ws = new WebSocket("ws://127.0.0.1:8888/secure_check")
        openWS(messageContainer, ws)  
        sendMessage("keycheck", ws)
        alert("检测已经开始，可能会占用wifi一段时间，请耐心等待~")
    })

    $("#midman_button").click(function(){
        //alert("test")
        var ws = new WebSocket("ws://127.0.0.1:8888/secure_check")
        openWS(messageContainer, ws)  
        sendMessage("midmancheck", ws)

    })
    


})

function clearContent(idname){
    document.getElementById(idname).innerHTML = ""
}

// key function
function openWS(messageContainer, ws) {
  
    ws.onopen = function(e){    //连接成功后的回调函数
      
    }
    ws.onmessage = function(e) {  //收到服务器数据之后的回调函数
        var data = JSON.parse(e.data)
        messageContainer.appendChild(createChatEntry(data.message))
        scrollToBottom()
    };
    ws.onclose = function(e) {
        messageContainer.appendChild(createChatEntry("======================================"))
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
    sys_msg.innerHTML = ">>&nbsp;&nbsp; " + message
    entry.appendChild(sys_msg)

    return entry
}

//让浏览器滚动条保持在最低部
function scrollToBottom(){
    // w.scrollTo(0, window.getElementById("chatbox").innerHeight);
    var obj = document.getElementById('chatbox');
    obj.scrollTop = obj.scrollHeight;
    //清除消息框
    //document.getElementById("message").value="";
}
  
  
//ws.send()用于向后端发送数据


//发送wifi名称
function reg(wifiname, ws){
    var data = { 
        type: "reg",
        wifiname: wifiname
    }
    sendMsg(JSON.stringify(data), ws)
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
