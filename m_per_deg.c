/* -*- tab-width: 2; mode: c; -*-
 * 
 * Calculate m/degree latitude and longitude
 * 
 * The algorithm is from Jean Meeus's Astronomical Algorithms.
 * 
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include <math.h>

void calc_m_per_deg(double,double *,double *);

/*
 *
 */

#ifdef STANDALONE

int main(int argc,char *argv[]) {

  double lat, m_deg_lat, m_deg_long;

  calc_m_per_deg(lat = 0.0,&m_deg_lat,&m_deg_long);
  printf("lat. %5.1f, %6d m/deg. lat., %6d m/deg. long.\r\n",
         lat,(int) m_deg_lat,(int) m_deg_long);

  // Example 10.b
  calc_m_per_deg(lat = 42.0,&m_deg_lat,&m_deg_long);
  printf("lat. %5.1f, %6d m/deg. lat., %6d m/deg. long.\r\n",
         lat,(int) m_deg_lat,(int) m_deg_long);

  calc_m_per_deg(lat = 51.0,&m_deg_lat,&m_deg_long);
  printf("lat. %5.1f, %6d m/deg. lat., %6d m/deg. long.\r\n",
         lat,(int) m_deg_lat,(int) m_deg_long);

  return 0;
}

#endif

/*
 *
 */

void calc_m_per_deg(double lat_d,double *m_deg_lat,double *m_deg_long) {

  double pi, deg2rad, sin_lat, cos_lat,
         a = 6378140.0, c, d, e = 0.08181922, Rp = 0.0, Rm = 0.0;
  // double rho;

  pi          = 4.0 * atan(1.0);
  deg2rad     = pi / 180.0;

  lat_d      *= deg2rad;

  sin_lat     = sin(lat_d);
  cos_lat     = cos(lat_d);

  //  rho         = 0.9983271 + (0.0016764 * cos(2.0 * lat_d)) - (0.0000035 * cos(4.0 * lat_d));
  c           = e * sin_lat;
  d           = sqrt(1.0 - (c * c));
  Rp          = a * cos_lat / d;
  *m_deg_long = deg2rad * Rp;
  Rm          = a * (1.0 - (e * e)) / pow(d,3);
  *m_deg_lat  = deg2rad * Rm;

  return;
}

/*
 *
 */

