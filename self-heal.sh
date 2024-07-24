#!/bin/bash

# Define your nodes
NODES=("db1" "db2" "db3") # Replace with your actual node hostnames or IPs

# Function to check if a node is active
is_node_active() {
    local node=$1
    ssh ubuntu@"$node" "sudo systemctl is-active --quiet mysqld.service"
}

# Function to get the sequence number from galera_recovery
get_sequence_number() {
    local node=$1
    output=$(ssh ubuntu@"$node" "sudo galera_recovery")
    seq_num=$(echo "$output" | awk -F ':' '{print $2}')
    # echo "Debug: Extracted sequence number for $node: $output" >&2
    echo "$seq_num"
}

# Check if all nodes are down
all_down=true
for node in "${NODES[@]}"; do
    if is_node_active "$node"; then
        all_down=false
        break
    fi
done

if $all_down; then
    echo "All nodes are down. Proceeding to check sequence numbers..."

    # Get sequence numbers from all nodes
    declare -A seq_numbers
    for node in "${NODES[@]}"; do
        seq_num=$(get_sequence_number "$node")
        echo "$node : $seq_num"
        if [[ "$seq_num" =~ ^[0-9]+$ ]]; then
            seq_numbers["$node"]=$seq_num
        else
            echo "Warning: Invalid sequence number for $node"
            seq_numbers["$node"]=0
        fi
    done

    # Determine the node with the highest sequence number
    max_node=""
    max_seq_num=0
    for node in "${NODES[@]}"; do
        current_seq=${seq_numbers["$node"]}
        if [[ "$current_seq" =~ ^[0-9]+$ ]] && [ "$current_seq" -gt "$max_seq_num" ]; then
            max_seq_num=$current_seq
            max_node="$node"
        fi
    done

    if [ -n "$max_node" ]; then
        echo "Node with highest sequence number: $max_node with sequence number: $max_seq_num"

        # Run galera_new_cluster on the node with the highest sequence number
        echo "Running galera_new_cluster on $max_node..."
        ssh "$max_node" "sudo galera_new_cluster"

        # Start mysqld.service on other nodes
        for node in "${NODES[@]}"; do
            if [ "$node" != "$max_node" ]; then
                echo "Starting mysqld.service on $node..."
                ssh "$node" "sudo systemctl start mysqld.service"
            fi
        done
    else
        echo "Error: No valid sequence numbers found. Unable to determine which node to start."
    fi

else
    # At least one node is active
    echo "At least one node is active. Starting mysqld.service on remaining nodes..."
    for node in "${NODES[@]}"; do
        if ! is_node_active "$node"; then
            echo "Starting mysqld.service on $node..."
            ssh "$node" "sudo systemctl start mysqld.service"
        fi
    done
fi

