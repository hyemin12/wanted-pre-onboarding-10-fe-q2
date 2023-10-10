import { BASE_URL } from "./const.js";
import {
  getAccessTokenFromLocalStorage,
  saveAccessTokenToLocalStorage,
} from "../utils/accessTokenHandler.js";

import axios from "axios";

/*********
 *  실습 2-1
 * */

export const loginWithToken = async (args) => {
  // TODO(2-1): 로그인 API 호출 및 토큰 반환하기
  // POST, `${ BASE_URL }/auth/login`을 호출하세요.
  // API Spec은 강의 자료를 참고하세요.
  // access_token 발급에 성공한 경우에는 { result: 'success', access_token: string } 형태의 값을 반환하세요.

  const loginRes = await axios.post(`${BASE_URL}/auth/login`, args);

  if (loginRes)
    return { result: "success", access_token: loginRes.data.access_token };

  return {
    result: "fail",
    access_token: null,
  };
};

export const getCurrentUserInfoWithToken = async (token) => {
  // TODO(2-1): 함수에서 토큰을 직접 주입받아 사용하기
  // GET, `${ BASE_URL }/profile`을 호출하세요.
  // argument로 전달받은 token을 Authorization header에 Bearer token으로 넣어주세요.
  // API Spec은 강의 자료를 참고하세요.
  // 유저 정보 조회에 성공한 경우에는 UserInfo 타입의 값을 반환하세요.

  const userInfoRes = await axios.get(`${BASE_URL}/profile`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (userInfoRes) return userInfoRes.data;

  return null;
};

/*********
 *  실습 2-2
 * */

export const login = async (args) => {
  // TODO(2-2): 로그인 API 호출 및 access token 로컬스토리지에 저장하기
  // POST, `${ BASE_URL }/auth/login`을 호출하세요.
  // API Spec은 강의 자료를 참고하세요.
  // access_token 발급에 성공한 경우에는 saveAccessTokenToLocalStorage 함수를 호출하여 access_token을 localStorage에 저장하고 'success'를 반환하세요.

  const loginRes = await axios.post(`${BASE_URL}/auth/login`, args);

  if (loginRes) {
    saveAccessTokenToLocalStorage(loginRes.data.access_token);
    return "success";
  }

  return "fail";
};

export const getCurrentUserInfo = async () => {
  // TODO(2-2): 로컬스토리지에서 토큰을 가져와 사용하기
  // GET, `${ BASE_URL }/profile`을 호출하세요.
  // 로컬 스토리지에 있는 token을 getAccessTokenFromLocalStorage로 가져와서 Authorization header에 Bearer token으로 넣어주세요.
  // API Spec은 강의 자료를 참고하세요.
  // 유저 정보 조회에 성공한 경우에는 UserInfo 타입의 값을 반환하세요.

  const token = getAccessTokenFromLocalStorage();

  const userInfoResponse = await axios.get(`${BASE_URL}/profile`, {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });

  if (userInfoResponse) return userInfoResponse.data;

  return null;
};
