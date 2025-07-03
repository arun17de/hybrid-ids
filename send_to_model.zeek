event Conn::log_conn(rec: Conn::Info)
{
    # Optional field handling
    local service = "-";
    if ( rec?$service )
        service = rec$service;

    local state = "-";
    if ( rec?$conn_state )
        state = rec$conn_state;
        
    local dur: interval = 0secs;
    if (rec?$duration)
    	dur=rec$duration;  # Default to 0 if duration is missing

    local proto = rec$proto;
    local sbytes = rec$orig_bytes;
    local dbytes = rec$resp_bytes;
    local spkts = rec$orig_pkts;
    local dpkts = rec$resp_pkts;

    # Format into CSV string (8 fields total, label not included here)
    local features = fmt("%s,%s,%s,%f,%d,%d,%d,%d",
                         proto, service, state,
                         dur, sbytes, dbytes,
                         spkts, dpkts);

    # Call Python script with the feature string
    system(fmt("./tf_env/bin/python3 ./send_to_model.py '%s'", features));
}

