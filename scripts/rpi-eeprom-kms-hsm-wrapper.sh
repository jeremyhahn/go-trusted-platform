#!/bin/sh
set -eu

: "${RPI_EEPROM_FLEET_KEY:?set RPI_EEPROM_FLEET_KEY to a kms:// fleet key reference}"

PLATFORMCTL="${PLATFORMCTL:-platformctl}"

if [ -n "${RPI_EEPROM_FLEET_CERT:-}" ]; then
	exec "$PLATFORMCTL" diskimage rpi-eeprom-hsm \
		--fleet-key "$RPI_EEPROM_FLEET_KEY" \
		--fleet-cert "$RPI_EEPROM_FLEET_CERT" \
		"$@"
fi

exec "$PLATFORMCTL" diskimage rpi-eeprom-hsm \
	--fleet-key "$RPI_EEPROM_FLEET_KEY" \
	"$@"
