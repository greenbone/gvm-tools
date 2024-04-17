def alert_id(
    gmp: Gmp,
    alert_name: str,
):
    response_xml = gmp.get_alerts(filter_string="rows=-1, name=" + alert_name)
    alerts_xml = response_xml.xpath("alert")
    alert_id = ""

    for alert in alerts_xml:
        name = "".join(alert.xpath("name/text()"))
        alert_id = alert.get("id")
    return alert_id
