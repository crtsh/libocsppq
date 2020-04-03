/* libocsppq - perform OCSP checks from a PostgreSQL function
 * Written by Rob Stradling
 * Copyright (C) 2017-2020 Sectigo Limited
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

CREATE OR REPLACE FUNCTION ocsp_randomserial_embedded(
	issuer_cert				bytea,
	ocsp_url				text
) RETURNS text
AS $$
BEGIN
	RETURN ocsp_randomserial_check(encode(issuer_cert, 'base64'), ocsp_url);
END;
$$ LANGUAGE plpgsql STRICT;
