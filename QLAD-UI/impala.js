/*
 * QLAD - An anomaly detection system for DNS traffic
 * Copyright (C) 2017 DNS Belgium
 *
 * This file is part of QLAD.
 *
 * QLAD is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * QLAD is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with QLAD.  If not, see <http://www.gnu.org/licenses/>.
 */

const nodeImpala = require('node-impala');
var cfg = require("./config"); 

const client = nodeImpala.createClient();

client.connect({
  host: cfg.impala.host,
  port: cfg.impala.port,
  resultType: 'json-array'
})
.then(() => console.log("Connection to Impala successful."))
.catch(error => console.error("Connection to Impala failed: " + error));

module.exports = client;
