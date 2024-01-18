# Given the settings object, assign plots to each application metric.

def assign_plots(settings, figure):
    active_metrics = [key for key, value in settings["application"].items() if value]
    settings["plot_per_metric"] = {}
    number_of_plots = len(active_metrics)
    plots = {}

    if number_of_plots == 0:
        return None

    for i, metric in enumerate(active_metrics):
        plots[metric] = figure.add_subplot(number_of_plots, 1, i + 1)

    return plots
