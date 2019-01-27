window.onload = get_signature;

function get_signature () {
    function send_sig_request() {
        http.open('POST', url, true);
        //http.timeout = 5000;  // timeout not viable because of user interaction
        http.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
        http.send(params);
    }

    function handle_sig_response() {
        if(http.readyState == 4) {
            switch (http.status) {
                case 200:
                    if (http.responseText === undefined || http.responseText === '') {
                        submit_to_client('<error code=2 msg="There is no result to signature service on 127.0.0.1:8088"/>');
                    } else {
                        document.getElementsByName('XMLRequest')[0].value = http.responseText;
                        submit_to_client(http.responseText);
                    }
                    break;
                case 0:
                    submit_to_client('<error code=1 msg="could not connect to signature service on 127.0.0.1:8088"/>');
                    break;
                default:
                    break;
            }
        }
    }

    var http = new XMLHttpRequest();
    http.onreadystatechange = handle_sig_response;
    var url = 'http://localhost:8088/http-security-layer-request';
    var params = 'XMLRequest=' + document.getElementsByName('XMLRequest')[0].value;
    send_sig_request();
}

function submit_to_client(params) {
    function handle_client_response() {
        if (http.readyState == 4) {
            if (http.status != 200) {
                alert('Failed to answer signature creation request to ');
            } else {
                document.open();
                document.write(http.responseText);
                document.close();
            }
        }
    }
    var http = new XMLHttpRequest();
    var url = 'http://localhost:8080/sigresult';
    http.open('POST', url, true);
    http.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
    http.onreadystatechange = handle_client_response;
    http.send(params);
}
