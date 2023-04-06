from pwcthreatintelligence_connector import PwcThreatIntelligenceConnector


pwcti = PwcThreatIntelligenceConnector()

pwcti.config = {
    'Base_URL': 'https://synapse-api-v2-dot-pg-uk-n-app-595394.appspot.com',
    'API_KEY': 'YIoMlbmrq7kduQv7Jfh14G03iMQ',
    'full_url': 'https://synapse-api-v2-dot-pg-uk-n-app-595394.appspot.com/synapse/v2/ipv4s/45.93.31.122/tie',
    'IP_to_Lookup': '159.89.22.147'
}

#pwcti.initialize()

pwcti.action_identifier = 'lookup_hash'

pwcti.handle_action(
   {'hash': 'A300F4AA95E0D9055EC5E59CB651BA9A'}
)