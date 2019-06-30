package com.darren.demo.response;

import org.apache.commons.lang.StringUtils;

import java.util.ArrayList;
import java.util.List;

public class WsResponse<T> {

    private MessageCode status;
    private List<String> messages;
    private T result;

    public WsResponse() {
        messages = new ArrayList<>();
    }

    public WsResponse(MessageCode status, T result) {
        messages = new ArrayList<>();
        this.status = status;
        this.result = result;
    }

    public MessageCode getStatus() {
        return status;
    }

    public void setStatus(MessageCode status) {
        this.status = status;
    }

    public List<String> getMessages() {
        return messages;
    }

    public void setMessages(List<String> messages) {
        this.messages = messages;
    }

    public T getResult() {
        return result;
    }

    public void setResult(T result) {
        this.result = result;
    }

    @Override
    public String toString() {
        return "error code:" + status + " result:" + result;
    }

    public static WsResponse failure(String msg) {
        WsResponse resp = new WsResponse();
        resp.status = MessageCode.COMMON_FAILURE;
        resp.getMessages().add(msg);
        return resp;
    }

    public static WsResponse failure(MessageCode messageCode) {
        WsResponse resp = new WsResponse();
        resp.status = messageCode;
        resp.getMessages().add(messageCode.getMsg());
        return resp;
    }

    public static WsResponse failure(MessageCode messageCode, String message) {
        WsResponse resp = new WsResponse();
        resp.status = messageCode;
        if(StringUtils.isNotBlank(messageCode.getMsg())){
        	resp.getMessages().add(messageCode.getMsg());
        }
        if (StringUtils.isNotBlank(message)) {
            resp.getMessages().add(message);
        }
        return resp;
    }

    public static WsResponse success() {
        WsResponse resp = new WsResponse();
        resp.status = MessageCode.COMMON_SUCCESS;
        resp.getMessages().add(MessageCode.COMMON_SUCCESS.getMsg());
        return resp;
    }

    public static <K> WsResponse<K> success(K t) {
        WsResponse<K> resp = new WsResponse<>();
        resp.status = MessageCode.COMMON_SUCCESS;
        resp.getMessages().add(MessageCode.COMMON_SUCCESS.getMsg());
        resp.result = t;

        return resp;
    }

    /**
     * 判断字符串是否已经是 WsResponse返回格式
     *
     * @param json
     * @return
     */
    public static boolean isWsResponseJson(String json) {
        if (json != null && json.indexOf("\"status\":") != -1
                && json.indexOf("\"messages\":") != -1
                && json.indexOf("\"result\":") != -1) {
            return true;
        } else {
            return false;
        }
    }
}
