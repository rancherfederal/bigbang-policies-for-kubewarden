#!/bin/bash

for file in $(ls ./constraint-templates/*_*.yaml); do
    cat $file | sed '/apiVersion/,/rego:/d' | sed 's/^        //' > ./policies/$(basename $file | sed 's/yaml/rego/')
done

for file in $(ls ./constraint-templates/K8sPSP*.yaml); do
    cat $file | sed '/apiVersion/,/rego:/d' | sed 's/^      //' | grep -v "target: admission.k8s.gatekeeper.sh" > ./policies/$(basename $file | sed 's/yaml/rego/')
done