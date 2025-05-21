#!/usr/bin/env python3

import argparse
import json
import os
import jinja2

def generate_report(data_file, template_file, output_file):
    """Generate a report from data file and template"""
    
    # Load data
    with open(data_file, 'r') as f:
        data = json.load(f)
    
    # Load template
    template_dir = os.path.dirname(template_file)
    template_name = os.path.basename(template_file)
    
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(template_dir)
    )
    template = env.get_template(template_name)
    
    # Render template
    rendered = template.render(**data)
    
    # Write output
    with open(output_file, 'w') as f:
        f.write(rendered)
    
    print(f"Report generated successfully: {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate a report from data file and template')
    parser.add_argument('data_file', help='JSON data file')
    parser.add_argument('template_file', help='HTML template file')
    parser.add_argument('output_file', help='Output HTML file')
    
    args = parser.parse_args()
    
    generate_report(args.data_file, args.template_file, args.output_file)