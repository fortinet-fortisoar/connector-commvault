""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from connectors.core.connector import get_logger, ConnectorError, Connector
from .operations import operations, check_health_ex

logger = get_logger("commvault")


class Commvault(Connector):
    def execute(self, config, operation, params, **kwargs):
        try:
            connector_info = {"connector_name": self._info_json.get("name"),
                              "connector_version": self._info_json.get("version")}
            operation = operations.get(operation)
        except Exception as err:
            logger.exception(err)
            raise ConnectorError(err)
        return operation(config, params, connector_info)

    def check_health(self, config):
        logger.info("starting health check")
        connector_info = {"connector_name": self._info_json.get("name"),
                          "connector_version": self._info_json.get("version")}
        check_health_ex(config, connector_info)
        logger.info("completed health check no errors")
