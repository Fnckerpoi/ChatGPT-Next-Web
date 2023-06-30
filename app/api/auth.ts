import { NextRequest } from "next/server";
import { getServerSideConfig } from "../config/server";
import md5 from "spark-md5";
import { ACCESS_CODE_PREFIX } from "../constant";

function getIP(req: NextRequest) {
  let ip = req.ip ?? req.headers.get("x-real-ip");
  const forwardedFor = req.headers.get("x-forwarded-for");

  if (!ip && forwardedFor) {
    ip = forwardedFor.split(",").at(0) ?? "";
  }

  return ip;
}

function parseApiKey(bearToken: string) {
  const token = bearToken.trim().replaceAll("Bearer ", "").trim();
  const isOpenAiKey = !token.startsWith(ACCESS_CODE_PREFIX);
  console.log("isOpenAiKey？", isOpenAiKey);
  return {
    accessCode: isOpenAiKey ? "" : token.slice(ACCESS_CODE_PREFIX.length),
    apiKey: isOpenAiKey ? token : "",
  };
}

export function auth(req: NextRequest) {
  const authToken = req.headers.get("Authorization") ?? "";
  // check if it is openai api key or user token
  const { accessCode, apiKey: token } = parseApiKey(authToken);
  const hashedCode = md5.hash(accessCode ?? "").trim();
  const serverConfig = getServerSideConfig();
  console.log("[Auth] allowed hashed codes: ", [...serverConfig.codes]);
  console.log("[Auth] authToken: ", authToken);
  console.log("[Auth] accessCode:", { accessCode, apiKey: token });
  console.log("[Auth] hashedCode:", hashedCode);
  console.log("[Auth] TOKEN:", token);
  console.log("[请求IP] ", getIP(req));
  console.log("[请求时间] ", new Date().toLocaleString());

  if (serverConfig.needCode && !serverConfig.codes.has(hashedCode) && !token) {
    return {
      error: true,
      msg: !accessCode ? "empty access code" : "wrong access code",
    };
  }
  console.log("{ accessCode, apiKey: token }", { accessCode, apiKey: token });
  // if user does not provide an api key, inject system api key
  if (token) {
    //TODO：从这里向后端接口请求获取api key，提供本地缓存的Token
    const apiKey = serverConfig.apiKey;
    console.log("apiKey:", apiKey);
    if (apiKey) {
      console.log("[Auth] use system api key");
      req.headers.set("Authorization", `Bearer ${apiKey}`);
    } else {
      console.log("[Auth] admin did not provide an api key");
    }
  } else {
    console.log("[Auth] use user api key");
  }
  console.log("权限验证完成");
  return {
    error: false,
  };
}
