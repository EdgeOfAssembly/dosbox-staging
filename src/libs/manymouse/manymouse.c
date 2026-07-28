/*
 * ManyMouse foundation code; apps talks to this and it talks to the lowlevel
 *  code for various platforms.
 *
 * Please see the file LICENSE.txt in the source's root directory.
 *
 *  This file written by Ryan C. Gordon.
 *  Altered to:
 *   - prefer modern evdev API over xinput on Linux, by Roman Standzikowski.
 */

#include <stdlib.h>
#include "manymouse.h"

static const char *manymouse_copyright =
    "ManyMouse " MANYMOUSE_VERSION " copyright (c) 2005-2012 Ryan C. Gordon.";

/* Linux+X11-only fork: only build/link evdev + XInput2 backends. */
extern const ManyMouseDriver *ManyMouseDriver_evdev;
extern const ManyMouseDriver *ManyMouseDriver_xinput2;

static const ManyMouseDriver **mice_drivers[] =
{
    &ManyMouseDriver_evdev,
    &ManyMouseDriver_xinput2,
};


static const ManyMouseDriver *driver = NULL;

int ManyMouse_Init(void)
{
    const int upper = (sizeof (mice_drivers) / sizeof (mice_drivers[0]));
    int i;
    int retval = -1;

    /* impossible test to keep manymouse_copyright linked into the binary. */
    if (manymouse_copyright == NULL)
        return -1;

    if (driver != NULL)
        return -1;

    for (i = 0; (i < upper) && (driver == NULL); i++)
    {
        const ManyMouseDriver *this_driver = *(mice_drivers[i]);
        if (this_driver != NULL) /* if not built for this platform, skip it. */
        {
            const int mice = this_driver->init();
            if (mice > retval)
                retval = mice; /* may move from "error" to "no mice found". */

            if (mice >= 0)
                driver = this_driver;
        } /* if */
    } /* for */

    return retval;
} /* ManyMouse_Init */


void ManyMouse_Quit(void)
{
    if (driver != NULL)
    {
        driver->quit();
        driver = NULL;
    } /* if */
} /* ManyMouse_Quit */

const char *ManyMouse_DriverName(void)
{
    return (driver) ? driver->driver_name : NULL;
} /* ManyMouse_DriverName */

const char *ManyMouse_DeviceName(unsigned int index)
{
    return (driver) ? driver->name(index) : NULL;
} /* ManyMouse_DeviceName */

int ManyMouse_PollEvent(ManyMouseEvent *event)
{
    return (driver) ? driver->poll(event) : 0;
} /* ManyMouse_PollEvent */

/* end of manymouse.c ... */

