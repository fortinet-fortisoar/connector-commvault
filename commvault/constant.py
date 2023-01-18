""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

EXPIRY_TIME = 29  # token expiry time in minutes


class Method:
    GET = "GET"
    POST = "POST"


class Endpoint:
    LOGIN = "/Login"
    ALERT_RULE = "/AlertRule"
    USER = "/User"
